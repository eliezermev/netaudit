"""Tests del parseo de un XML de ejemplo de nmap y del pipeline de analisis."""

from __future__ import annotations

import os
import sys
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from netscan.fingerprints import (  # noqa: E402
    analizar_servicios,
    extraer_http,
    extraer_tls,
)
from netscan.scanner import (  # noqa: E402
    ErrorDeEscaneo,
    ResultadoEscaneo,
    parsear_xml_nmap,
    envolver_xml_lote,
)
from netscan.targets import validar_objetivo  # noqa: E402
from netscan.vulns import calcular_resumen, evaluar  # noqa: E402

RUTA_XML = os.path.join(RAIZ, "tests", "data", "ejemplo_nmap.xml")


def cargar_xml() -> str:
    with open(RUTA_XML, "r", encoding="utf-8") as manejador:
        return manejador.read()


def construir_resultado() -> ResultadoEscaneo:
    resultado = parsear_xml_nmap(cargar_xml())
    resultado.nmap_version = "Nmap version 7.80 ( https://nmap.org )"
    resultado.perfil = "completo"
    return resultado


class TestParseoXml(unittest.TestCase):
    def setUp(self):
        self.resultado = construir_resultado()

    def test_raiz_nmaprun(self):
        self.assertIsInstance(self.resultado, ResultadoEscaneo)

    def test_numero_de_hosts(self):
        self.assertEqual(len(self.resultado.hosts), 3)

    def test_hosts_activos(self):
        self.assertEqual(len(self.resultado.hosts_activos), 3)
        direcciones = sorted(h.direccion for h in self.resultado.hosts_activos)
        self.assertEqual(direcciones, ["192.168.1.1", "192.168.1.10", "192.168.1.15"])

    def test_hostnames(self):
        host = self.resultado.buscar_host("192.168.1.1")
        self.assertIsNotNone(host)
        self.assertEqual(host.hostnames, ["router.lan"])

    def test_puertos_totales_y_abiertos(self):
        # 6 + 7 + 1 = 14 puertos abiertos en el XML de ejemplo.
        self.assertEqual(self.resultado.total_puertos_abiertos, 14)

    def test_protocolo_y_puerto(self):
        host = self.resultado.buscar_host("192.168.1.1")
        puertos = {(p.puerto, p.protocolo) for p in host.puertos_abiertos}
        self.assertIn((22, "tcp"), puertos)
        self.assertIn((445, "tcp"), puertos)

    def test_metadatos_de_servicio(self):
        host = self.resultado.buscar_host("192.168.1.1")
        ssh = next(s for s in host.puertos_abiertos if s.puerto == 22)
        self.assertEqual(ssh.servicio, "ssh")
        self.assertEqual(ssh.producto, "OpenSSH")
        self.assertEqual(ssh.version, "7.4")
        self.assertIn("7.4", ssh.banner)

    def test_scripts_parsed(self):
        host = self.resultado.buscar_host("192.168.1.1")
        smb = next(s for s in host.puertos_abiertos if s.puerto == 445)
        self.assertTrue(any("smb-os-discovery" == i for i, _ in smb.scripts))
        self.assertTrue(any("NT LM 0.12" in s for _i, s in smb.scripts))

    def test_scripts_de_host(self):
        host = self.resultado.buscar_host("192.168.1.1")
        self.assertTrue(any(i == "smb2-time" for i, _ in host.scripts_host))

    def test_deteccion_de_so(self):
        host = self.resultado.buscar_host("192.168.1.1")
        self.assertTrue(host.os_nombre)
        self.assertGreater(host.os_precision, 0)

    def test_metadatos_de_ejecucion(self):
        self.assertTrue(self.resultado.inicio)
        self.assertTrue(self.resultado.fin)

    def test_xml_crudo_se_conserva(self):
        self.assertIn("<nmaprun", self.resultado.xml_crudo)

    def test_xml_truncado_falla_con_mensaje_util(self):
        xml = cargar_xml()
        truncado = xml[: len(xml) // 2]
        with self.assertRaises(ErrorDeEscaneo) as contexto:
            parsear_xml_nmap(truncado)
        mensaje = str(contexto.exception)
        self.assertIn("truncado", mensaje)

    def test_xml_vacio_falla(self):
        with self.assertRaises(ErrorDeEscaneo):
            parsear_xml_nmap("")

    def test_xml_no_nmaprun_falla(self):
        with self.assertRaises(ErrorDeEscaneo):
            parsear_xml_nmap("<otra_cosa><a/></otra_cosa>")


class TestFingerprints(unittest.TestCase):
    def setUp(self):
        self.resultado = construir_resultado()
        self.observaciones = analizar_servicios(self.resultado)

    def test_numero_de_observaciones(self):
        self.assertEqual(len(self.observaciones), 14)

    def test_detecta_telnet(self):
        telnet = next(o for o in self.observaciones if o.servicio.puerto == 23)
        self.assertTrue(telnet.datos.get("telnet"))

    def test_detecta_ftp_anonimo(self):
        ftp = next(o for o in self.observaciones if o.servicio.puerto == 21)
        self.assertTrue(ftp.datos.get("ftp_anonimo"))
        self.assertTrue(ftp.datos.get("ftp_sin_tls"))

    def test_detecta_smbv1(self):
        smb = next(o for o in self.observaciones if o.servicio.puerto == 445)
        self.assertTrue(smb.datos.get("smbv1"))

    def test_detecta_snmp_community(self):
        snmp = next(o for o in self.observaciones if o.servicio.puerto == 161)
        self.assertEqual(snmp.datos.get("snmp_community"), "public")

    def test_detecta_redis(self):
        redis = next(o for o in self.observaciones if o.servicio.puerto == 6379)
        self.assertTrue(redis.datos.get("redis_presente"))

    def test_detecta_puerto_administracion(self):
        admin = next(o for o in self.observaciones if o.servicio.puerto == 8161)
        self.assertEqual(admin.datos.get("puerto_administracion"), 8161)

    def test_extrae_http(self):
        http = next(o for o in self.observaciones if o.servicio.puerto == 80)
        cab = http.datos.get("http")
        self.assertIsNotNone(cab)
        self.assertEqual(cab.codigo, "200")
        self.assertIn("2.2.4", cab.servidor)
        self.assertIn("PUT", cab.metodos)
        self.assertTrue(cab.cookies)

    def test_extrae_tls(self):
        host = self.resultado.buscar_host("192.168.1.15")
        servicio = next(s for s in host.puertos_abiertos if s.puerto == 443)
        info = extraer_tls(servicio)
        self.assertIsNotNone(info)
        self.assertTrue(info.autofirmado)
        self.assertTrue(info.expirado)
        self.assertTrue(info.protocolo_obsoleto)
        self.assertIn("TLSv1", info.protocolo)
        self.assertFalse(info.sni_soportado)

    def test_extraer_http_devuelve_none_sin_scripts_http(self):
        """Un host solo con scripts ssl-* no debe inventar cabeceras HTTP."""
        host = self.resultado.buscar_host("192.168.1.15")
        servicio = next(s for s in host.puertos_abiertos if s.puerto == 443)
        self.assertIsNone(extraer_http(servicio))
        self.assertIsNotNone(extraer_tls(servicio))


class TestMotorDeReglas(unittest.TestCase):
    def setUp(self):
        self.resultado = construir_resultado()
        self.hallazgos = evaluar(self.resultado)

    def _ids(self):
        return {h.regla for h in self.hallazgos}

    def test_se_detectan_hallazgos(self):
        self.assertGreater(len(self.hallazgos), 0)

    def test_reglas_clave_disparadas(self):
        ids = self._ids()
        for esperada in (
            "TELNET_ABIERTO",
            "FTP_ANONIMO",
            "FTP_SIN_TLS",
            "SMBV1",
            "SNMP_COMMUNITY_DEBIL",
            "SSH_VERSION_ANTIGUA",
            "PUERTO_ADMIN_EXPUESTO",
            "SERVICIO_DATOS_SIN_AUTH",
            "HTTP_METODOS_PELIGROSOS",
            "HTTP_RUTA_SENSIBLE",
            "HTTP_CABECERAS_INSEGURAS",
            "TLS_DEBIL",
        ):
            self.assertIn(esperada, ids, f"no disparo la regla {esperada}")

    def test_telnet_es_critica(self):
        telnet = next(h for h in self.hallazgos if h.regla == "TELNET_ABIERTO")
        self.assertEqual(telnet.severidad, "CRITICA")

    def test_smbv1_es_critica(self):
        smb = next(h for h in self.hallazgos if h.regla == "SMBV1")
        self.assertEqual(smb.severidad, "CRITICA")

    def test_snmp_es_critica(self):
        snmp = next(h for h in self.hallazgos if h.regla == "SNMP_COMMUNITY_DEBIL")
        self.assertEqual(snmp.severidad, "CRITICA")

    def test_hallazgos_ordenados_por_severidad(self):
        orden = ["CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"]
        indices = [orden.index(h.severidad) for h in self.hallazgos]
        self.assertEqual(indices, sorted(indices))

    def test_cada_hallazgo_tiene_evidencia_y_mitigacion(self):
        for hallazgo in self.hallazgos:
            self.assertTrue(hallazgo.evidencia.strip(), hallazgo.regla)
            self.assertTrue(hallazgo.mitigacion.strip(), hallazgo.regla)
            self.assertTrue(hallazgo.riesgo.strip(), hallazgo.regla)
            self.assertTrue(hallazgo.falsos_positivos.strip(), hallazgo.regla)

    def test_resumen_cuenta_por_severidad(self):
        resumen = calcular_resumen(self.hallazgos)
        self.assertEqual(sum(resumen.por_severidad.values()), len(self.hallazgos))
        self.assertEqual(resumen.total, len(self.hallazgos))
        self.assertTrue(0 <= resumen.score <= 100)
        self.assertGreater(resumen.por_severidad["CRITICA"], 0)


class TestXmlPorLotes(unittest.TestCase):
    """El XML concatenado de varios lotes debe seguir siendo XML valido."""

    def setUp(self):
        with open(RUTA_XML, "r", encoding="utf-8") as manejador:
            self.xml = manejador.read()
        self.resultado = parsear_xml_nmap(self.xml)

    def _lotes(self, numero: int = 3):
        """Devuelve la lista de XML de cada lote, ya envueltos."""
        return [
            envolver_xml_lote(self.xml, indice, numero, ResultadoEscaneo(objetivos=[]))
            for indice in range(1, numero + 1)
        ]

    def _lotes_txt(self, numero: int = 3):
        """Los mismos lotes unidos como texto (formato antiguo sin raiz)."""
        return "\n\n".join(self._lotes(numero))

    def test_envolver_quita_la_etiqueta_original_con_atributos(self):
        envuelto = envolver_xml_lote(self.xml, 1, 2, ResultadoEscaneo(objetivos=[]))
        self.assertTrue(envuelto.startswith('<nmaprun lote="1/2"'))
        # No debe quedar la etiqueta original de nmap con sus atributos.
        self.assertNotIn('scanner="nmap"', envuelto)
        self.assertEqual(envuelto.count("<nmaprun"), 1)
        self.assertEqual(envuelto.count("</nmaprun>"), 1)

    def test_xml_concatenado_es_valido(self):
        import xml.etree.ElementTree as ET

        from netscan.scanner import unir_lotes_xml

        # Un unico lote se deja tal cual.
        ET.fromstring(unir_lotes_xml(self._lotes(1)))
        # Varios lotes se envuelven en una raiz unica, de modo que el fichero
        # sea XML bien formado y lo puedan leer las herramientas estandar.
        raiz = ET.fromstring(unir_lotes_xml(self._lotes(3), "puertos", 3))
        self.assertEqual(raiz.tag, "netaudit_lotes")
        self.assertEqual(len(raiz.findall("nmaprun")), 3)

    def test_parseo_de_lotes_recupera_los_hosts(self):
        from netscan.scanner import parsear_xml_lotes, unir_lotes_xml

        combinado = parsear_xml_lotes(unir_lotes_xml(self._lotes(3), "puertos", 3))
        self.assertEqual(len(combinado.hosts), 3 * len(self.resultado.hosts))
        self.assertEqual(len(combinado.hosts_activos), 3 * len(self.resultado.hosts_activos))
        self.assertEqual(
            combinado.total_puertos_abiertos,
            3 * self.resultado.total_puertos_abiertos,
        )

    def test_parseo_de_lotes_tolera_formato_antiguo(self):
        """Debe leer tambien varios <nmaprun> sueltos sin raiz commun."""
        from netscan.scanner import parsear_xml_lotes

        combinado = parsear_xml_lotes(self._lotes_txt(2))
        self.assertEqual(len(combinado.hosts), 2 * len(self.resultado.hosts))

    def test_parseo_de_lotes_tolera_xml_de_nmap_directo(self):
        from netscan.scanner import parsear_xml_lotes

        resultado = parsear_xml_lotes(self.xml)
        self.assertEqual(len(resultado.hosts), len(self.resultado.hosts))

    def test_parseo_de_lotes_detecta_duplicados(self):
        """Un nmaprun invalido debe dar error, no datos corruptos."""
        from netscan.scanner import parsear_xml_lotes

        with self.assertRaises(ErrorDeEscaneo):
            parsear_xml_lotes("<nmaprun><host></nmaprun>")

    def test_parseo_de_lotes_vacio(self):
        from netscan.scanner import parsear_xml_lotes

        with self.assertRaises(ErrorDeEscaneo):
            parsear_xml_lotes("   ")


class TestLotesObjetivos(unittest.TestCase):
    def test_division_por_hosts(self):
        from netscan.scanner import dividir_en_lotes

        objetivos = [validar_objetivo("192.168.1.1") for _ in range(5)]
        lotes = dividir_en_lotes(objetivos, hosts_por_lote=2)
        self.assertEqual([len(l) for l in lotes], [2, 2, 1])

    def test_un_solo_lote_si_cabe(self):
        from netscan.scanner import dividir_en_lotes

        objetivos = [validar_objetivo("192.168.1.1")]
        self.assertEqual(len(dividir_en_lotes(objetivos, 256)), 1)

    def test_agrupar_por_tamano_de_red(self):
        from netscan.scanner import dividir_en_lotes

        objetivos = [validar_objetivo("192.168.1.0/24"), validar_objetivo("10.0.0.1")]
        # Un /24 son 256 hosts: con un lote de 200 no cabe junto al siguiente.
        lotes = dividir_en_lotes(objetivos, hosts_por_lote=200)
        self.assertEqual(len(lotes), 2)
        self.assertEqual([str(o) for o in lotes[0]], [str(objetivos[0])])

    def test_agrupar_respeta_el_limite(self):
        from netscan.scanner import dividir_en_lotes

        objetivos = [validar_objetivo(f"192.168.1.{i}") for i in range(1, 8)]
        for limite in (1, 2, 3, 5, 7, 10):
            lotes = dividir_en_lotes(objetivos, hosts_por_lote=limite)
            total = sum(len(l) for l in lotes)
            self.assertEqual(total, len(objetivos), f"se perdieron objetivos con {limite}")
            for lote in lotes:
                self.assertLessEqual(len(lote), limite)


class TestConstruccionComandoNmap(unittest.TestCase):
    """El comando debe ser siempre una LISTA, con los flags correctos."""

    def _info(self):
        from netscan.osdetect import InfoNmap

        return InfoNmap("nmap", "Nmap 7.94", (7, 94, 0), "PATH", "")

    def _comando(self, **kwargs):
        from netscan.scanner import construir_comando_nmap

        base = dict(
            info_nmap=self._info(),
            objetivos_nmap=["192.168.1.0/24"],
            perfil="puertos",
            velocidad="T4",
            xml_ruta="salida.xml",
        )
        base.update(kwargs)
        return construir_comando_nmap(**base)

    def test_siempre_es_una_lista(self):
        comando = self._comando()
        self.assertIsInstance(comando, list)
        self.assertTrue(all(isinstance(argumento, str) for argumento in comando))
        self.assertEqual(comando[0], "nmap")

    def test_perfil_puertos(self):
        comando = self._comando()
        self.assertIn("-sT", comando)
        self.assertIn("-sV", comando)
        self.assertIn("--top-ports", comando)
        self.assertEqual(comando[comando.index("--top-ports") + 1], "1000")
        self.assertNotIn("-sS", comando, "-sS solo si el usuario lo pide")

    def test_sin_solo_se_pide_por_usuario(self):
        comando = self._comando(usar_ss=True)
        self.assertIn("-sS", comando)
        self.assertNotIn("-sT", comando, "-sT y -sS son incompatibles")

    def test_perfil_discovery(self):
        comando = self._comando(perfil="discovery")
        self.assertIn("-sn", comando)

    def test_perfil_web(self):
        comando = self._comando(perfil="web")
        self.assertIn("--script", comando)
        self.assertEqual(comando[comando.index("--script") + 1], "http-*")

    def test_perfil_completo(self):
        comando = self._comando(perfil="completo")
        for flag in ("-sV", "-sC", "-A"):
            self.assertIn(flag, comando)

    def test_velocidad_se_aplica(self):
        for velocidad in ("T2", "T3", "T4", "T5"):
            self.assertIn(f"-{velocidad}", self._comando(velocidad=velocidad))

    def test_velocidad_invalida_falla(self):
        with self.assertRaises(ErrorDeEscaneo):
            self._comando(velocidad="T9")

    def test_puertos_usuario_reemplazan_los_del_perfil(self):
        comando = self._comando(perfil="web", puertos="22,80")
        self.assertEqual(comando[comando.index("-p") + 1], "22,80")

    def test_xml_siempre_indicado(self):
        comando = self._comando()
        self.assertEqual(comando[comando.index("-oX") + 1], "salida.xml")

    def test_objetivo_al_final(self):
        comando = self._comando()
        self.assertEqual(comando[-1], "192.168.1.0/24")

    def test_exclusiones(self):
        comando = self._comando(excluir=["10.0.0.0/8", "10.1.1.1"])
        self.assertEqual(comando[comando.index("--exclude") + 1], "10.0.0.0/8,10.1.1.1")

    def test_host_timeout(self):
        comando = self._comando(host_timeout="30s")
        self.assertEqual(comando[comando.index("--host-timeout") + 1], "30s")

    def test_perfil_inexistente_falla(self):
        with self.assertRaises(ErrorDeEscaneo):
            self._comando(perfil="inventado")

    def test_sin_objetivos_falla(self):
        with self.assertRaises(ErrorDeEscaneo):
            self._comando(objetivos_nmap=[])

    def test_entrada_de_usuario_no_se_concatena(self):
        """Un objetivo con caracteres de shell debe ir como argumento propio."""
        objetivo = "192.168.1.1; echo pwned"
        comando = self._comando(objetivos_nmap=[objetivo])
        # Aparece como un unico argumento, no fusionado en la linea de comando.
        self.assertIn(objetivo, comando)
        self.assertEqual(comando.count(objetivo), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
