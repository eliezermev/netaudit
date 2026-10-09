"""Tests unitarios de validacion de objetivos (netscan/targets.py)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscan.targets import (  # noqa: E402
    TIPO_CIDR,
    TIPO_HOSTNAME,
    TIPO_IP,
    TIPO_RANGO,
    ObjetivoInvalido,
    construir_exclusiones,
    construir_objetivos,
    es_cidr,
    es_hostname,
    es_ipv4,
    filtrar_excluidos,
    normalizar_rango,
    validar_exclusion,
    validar_objetivo,
)


class TestPrimitivas(unittest.TestCase):
    def test_es_ipv4(self):
        self.assertTrue(es_ipv4("192.168.1.1"))
        self.assertTrue(es_ipv4("0.0.0.0"))
        self.assertFalse(es_ipv4("192.168.1"))
        self.assertFalse(es_ipv4("192.168.1.256"))
        self.assertFalse(es_ipv4("host.lan"))
        self.assertFalse(es_ipv4(""))

    def test_es_cidr(self):
        self.assertTrue(es_cidr("192.168.1.0/24"))
        self.assertTrue(es_cidr("10.0.0.0/8"))
        self.assertFalse(es_cidr("192.168.1.0/33"))
        self.assertFalse(es_cidr("192.168.1.0"))
        self.assertFalse(es_cidr("192.168.1.0/abc"))

    def test_es_hostname(self):
        self.assertTrue(es_hostname("host"))
        self.assertTrue(es_hostname("host.lan"))
        self.assertTrue(es_hostname("a.b.c.example.com"))
        self.assertFalse(es_hostname("host..lan"))
        self.assertFalse(es_hostname("-host.lan"))
        self.assertFalse(es_hostname("host.lan-"))
        self.assertFalse(es_hostname("a" * 64 + ".lan"))
        self.assertFalse(es_hostname("x" * 300))


class TestNormalizarRango(unittest.TestCase):
    def test_rango_corto_se_expande(self):
        self.assertEqual(normalizar_rango("192.168.1.1-50"), "192.168.1.1-192.168.1.50")

    def test_rango_completo(self):
        self.assertEqual(
            normalizar_rango("192.168.1.10-192.168.1.20"), "192.168.1.10-192.168.1.20"
        )

    def test_rango_invertido_falla(self):
        with self.assertRaises(ObjetivoInvalido):
            normalizar_rango("192.168.1.50-10")

    def test_rango_malformado_falla(self):
        with self.assertRaises(ObjetivoInvalido):
            normalizar_rango("192.168.1.1-abc")


class TestValidarObjetivo(unittest.TestCase):
    def test_ip_unica(self):
        objetivo = validar_objetivo("192.168.1.10")
        self.assertEqual(objetivo.tipo, TIPO_IP)
        self.assertEqual(objetivo.hosts_aproximados, 1)
        self.assertFalse(objetivo.sensible)

    def test_ip_inalida(self):
        with self.assertRaises(ObjetivoInvalido):
            validar_objetivo("999.1.1.1")

    def test_objetivo_vacio(self):
        with self.assertRaises(ObjetivoInvalido):
            validar_objetivo("   ")

    def test_cidr(self):
        objetivo = validar_objetivo("192.168.1.0/24")
        self.assertEqual(objetivo.tipo, TIPO_CIDR)
        self.assertEqual(objetivo.hosts_aproximados, 256)

    def test_cidr_supera_limite(self):
        with self.assertRaises(ObjetivoInvalido) as contexto:
            validar_objetivo("10.0.0.0/8", limite_hosts=1024)
        self.assertIn("supera el limite", str(contexto.exception))

    def test_rango(self):
        objetivo = validar_objetivo("192.168.1.1-50")
        self.assertEqual(objetivo.tipo, TIPO_RANGO)
        self.assertEqual(objetivo.hosts_aproximados, 50)
        self.assertEqual(objetivo.valor_normalizado, "192.168.1.1-192.168.1.50")

    def test_hostname(self):
        objetivo = validar_objetivo("servidor.lan")
        self.assertEqual(objetivo.tipo, TIPO_HOSTNAME)

    def test_espacios_en_objetivo_fallan(self):
        with self.assertRaises(ObjetivoInvalido):
            validar_objetivo("192.168.1.1 192.168.1.2")

    def test_0_0_0_0_rechazado_como_ip(self):
        with self.assertRaises(ObjetivoInvalido):
            validar_objetivo("0.0.0.0")


class TestSensibilidad(unittest.TestCase):
    def test_internet_entero_es_sensible(self):
        objetivo = validar_objetivo("0.0.0.0/0", limite_hosts=10_000_000)
        self.assertTrue(objetivo.sensible)
        self.assertTrue(any("Internet entero" in m for m in objetivo.motivos_sensibilidad))

    def test_loopback_es_sensible(self):
        objetivo = validar_objetivo("127.0.0.1")
        self.assertTrue(objetivo.sensible)
        self.assertTrue(any("loopback" in m for m in objetivo.motivos_sensibilidad))

    def test_multicast_es_sensible(self):
        objetivo = validar_objetivo("224.0.0.0/4")
        self.assertTrue(objetivo.sensible)

    def test_publico_es_sensible(self):
        objetivo = validar_objetivo("8.8.8.8")
        self.assertTrue(objetivo.sensible)
        self.assertTrue(
            any("publicas" in m for m in objetivo.motivos_sensibilidad),
            objetivo.motivos_sensibilidad,
        )

    def test_privada_no_exige_confirmacion_extra(self):
        objetivo = validar_objetivo("192.168.1.0/24")
        self.assertFalse(objetivo.sensible)

    def test_10_0_0_0_8_no_exige_confirmacion_extra(self):
        """Las redes privadas RFC1918 son el caso de uso normal: bastan AUTORIZADO."""
        objetivo = validar_objetivo("10.0.0.0/8", limite_hosts=20_000_000)
        self.assertFalse(objetivo.sensible)
        self.assertEqual(objetivo.motivos_sensibilidad, ())

    def test_rango_privado_que_supera_limite_sigue_rechazado(self):
        """Un /8 privado no es 'sensible', asi que el limite si se aplica."""
        with self.assertRaises(ObjetivoInvalido) as contexto:
            validar_objetivo("10.0.0.0/8", limite_hosts=1024)
        self.assertIn("supera el limite", str(contexto.exception))

    def test_rango_sensible_amplio_llega_a_confirmacion_extra(self):
        """0.0.0.0/0 debe pasar el limite para exigir la doble confirmacion."""
        objetivo = validar_objetivo("0.0.0.0/0", limite_hosts=1024)
        self.assertTrue(objetivo.sensible)
        self.assertTrue(any("Internet entero" in m for m in objetivo.motivos_sensibilidad))
        self.assertTrue(any("alcance muy amplio" in m for m in objetivo.motivos_sensibilidad))


class TestConstruirObjetivos(unittest.TestCase):
    def test_lista_multiple(self):
        objetivos, errores = construir_objetivos(["192.168.1.1,192.168.1.2", "host.lan"])
        self.assertEqual(len(objetivos), 3)
        self.assertEqual(errores, [])

    def test_duplicados_se_eliminan(self):
        objetivos, _ = construir_objetivos(["192.168.1.1", "192.168.1.1"])
        self.assertEqual(len(objetivos), 1)

    def test_uno_invalido_no_tira_el_resto(self):
        objetivos, errores = construir_objetivos(["192.168.1.1", "999.1.1.1", "10.0.0.5"])
        self.assertEqual(len(objetivos), 2)
        self.assertEqual(len(errores), 1)
        self.assertIn("999.1.1.1", errores[0])

    def test_cuadruplo_invalido_no_se_trata_como_hostname(self):
        """'999.1.1.1' tiene forma de IP: debe rechazarse, no aceptarse como dominio."""
        with self.assertRaises(ObjetivoInvalido):
            validar_objetivo("999.1.1.1")
        with self.assertRaises(ObjetivoInvalido):
            validar_objetivo("1.2.3.4.5")

    def test_sin_objetivos(self):
        objetivos, errores = construir_objetivos([])
        self.assertEqual(objetivos, [])
        self.assertTrue(errores)

    def test_archivo_de_objetivos(self):
        with tempfile.TemporaryDirectory() as temporal:
            ruta = os.path.join(temporal, "objetivos.txt")
            with open(ruta, "w", encoding="utf-8") as manejador:
                manejador.write("# comentario\n\n192.168.1.1\nhost.lan\n")
            objetivos, errores = construir_objetivos([], archivo=ruta)
        self.assertEqual(len(objetivos), 2)
        self.assertEqual(errores, [])

    def test_archivo_inexistente(self):
        with self.assertRaises(ObjetivoInvalido):
            construir_objetivos([], archivo="/no/existe/archivo.txt")


class TestExclusiones(unittest.TestCase):
    def test_validar_exclusion_ip(self):
        texto, red = validar_exclusion("192.168.1.5")
        self.assertEqual(texto, "192.168.1.5")
        self.assertEqual(str(red), "192.168.1.5")

    def test_validar_exclusion_cidr(self):
        _texto, red = validar_exclusion("192.168.1.0/28")
        self.assertEqual(str(red), "192.168.1.0/28")

    def test_exclusion_no_numerica_falla(self):
        with self.assertRaises(ObjetivoInvalido):
            validar_exclusion("host.lan")

    def test_filtrar_cidr_dentro_de_exclusion(self):
        objetivos, _ = construir_objetivos(["192.168.1.16/28", "10.0.0.1"])
        _textos, redes, _err = construir_exclusiones(["192.168.1.0/24"])
        conservados, excluidos = filtrar_excluidos(objetivos, redes)
        self.assertEqual(len(conservados), 1)
        self.assertEqual(conservados[0].valor_normalizado, "10.0.0.1")
        self.assertEqual(len(excluidos), 1)

    def test_sin_exclusiones_no_filtra(self):
        objetivos, _ = construir_objetivos(["192.168.1.1", "10.0.0.1"])
        conservados, excluidos = filtrar_excluidos(objetivos, [])
        self.assertEqual(len(conservados), 2)
        self.assertEqual(excluidos, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
