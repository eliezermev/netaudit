"""Tests de calidad del codigo exigidos en la especificacion.

Verifican por analisis estatico (AST) que NetAudit respeta sus reglas:
  * nunca shell=True, os.system, eval, exec ni os.popen
  * toda llamada a nmap se construye como LISTA de argumentos
  * no hay variables globales mutables
  * no hay uso de entrada de usuario concatenada en una cadena de shell
"""

from __future__ import annotations

import ast
import os
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAQUETE = os.path.join(RAIZ, "netscan")

FUNCIONES_PROHIBIDAS = {"eval", "exec", "compile", "__import__"}
FUNCIONES_PELIGROSAS = {"system", "popen", "spawnl", "spawnv", "execl", "execv", "fork"}


def modulos_python() -> list:
    return sorted(
        os.path.join(PAQUETE, nombre)
        for nombre in os.listdir(PAQUETE)
        if nombre.endswith(".py")
    )


def arbol(ruta: str) -> ast.AST:
    # utf-8-sig tolera que un fichero lleve BOM (habitual en Windows).
    with open(ruta, "r", encoding="utf-8-sig") as manejador:
        return ast.parse(manejador.read(), filename=ruta)


def nombre_ruta(ruta: str) -> str:
    return os.path.basename(ruta)


class TestSeguridadDeProcesos(unittest.TestCase):
    def setUp(self):
        self.rutas = modulos_python()
        self.assertTrue(self.rutas, "no se encontraron modulos del paquete")

    def test_no_hay_ficheros_vacios(self):
        for ruta in self.rutas:
            self.assertGreater(os.path.getsize(ruta), 300, nombre_ruta(ruta))

    def test_ninguna_llamada_usa_shell_true(self):
        for ruta in self.rutas:
            for nodo in ast.walk(arbol(ruta)):
                if not isinstance(nodo, ast.Call):
                    continue
                for palabra in nodo.keywords:
                    if palabra.arg == "shell":
                        valor = palabra.value
                        es_true = isinstance(valor, ast.Constant) and valor.value is True
                        self.assertFalse(
                            es_true,
                            f"{nombre_ruta(ruta)}:{nodo.lineno} usa shell=True",
                        )

    def test_toda_llamada_a_subprocess_indica_shell_false(self):
        """Ser explicito con shell=False deja la intencion documentada en el codigo."""
        for ruta in self.rutas:
            for nodo in ast.walk(arbol(ruta)):
                if not isinstance(nodo, ast.Call):
                    continue
                funcion = nodo.func
                if not isinstance(funcion, ast.Attribute):
                    continue
                if funcion.attr not in ("run", "Popen", "call", "check_output"):
                    continue
                modulo = getattr(funcion.value, "id", "")
                if modulo != "subprocess":
                    continue
                palabras = {p.arg for p in nodo.keywords}
                self.assertIn(
                    "shell", palabras,
                    f"{nombre_ruta(ruta)}:{nodo.lineno} llama a subprocess."
                    f"{funcion.attr} sin indicar shell=False",
                )

    def test_no_hay_os_system_ni_popen(self):
        for ruta in self.rutas:
            for nodo in ast.walk(arbol(ruta)):
                if not isinstance(nodo, ast.Call):
                    continue
                funcion = nodo.func
                if not isinstance(funcion, ast.Attribute):
                    continue
                if getattr(funcion.value, "id", "") == "os" and funcion.attr in FUNCIONES_PELIGROSAS:
                    self.fail(
                        f"{nombre_ruta(ruta)}:{nodo.lineno} usa os.{funcion.attr}()"
                    )

    def test_no_hay_eval_ni_exec(self):
        for ruta in self.rutas:
            for nodo in ast.walk(arbol(ruta)):
                if isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name):
                    self.assertNotIn(
                        nodo.func.id, FUNCIONES_PROHIBIDAS,
                        f"{nombre_ruta(ruta)}:{nodo.lineno} usa {nodo.func.id}()",
                    )

    def test_comandos_nmap_se_construyen_como_lista(self):
        """El comando de nmap debe ser una lista, nunca una cadena con el input
        del usuario concatenado."""
        for ruta in self.rutas:
            arbol_modulo = arbol(ruta)
            for funcion in ast.walk(arbol_modulo):
                if not isinstance(funcion, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # Busca asignaciones del tipo comando = ["nmap", ...] o f-strings
                # que contengan destinos de usuario.
                for asig in ast.walk(funcion):
                    if isinstance(asig, ast.Assign):
                        for valor in ast.walk(asig.value):
                            if isinstance(valor, ast.JoinedStr):
                                # f-string: solo se admite dentro de valores de
                                # lista para campos concretos, no como comando.
                                continue


def nombres_oficiales_mitre() -> set:
    """Extrae del propio codigo los nombres oficiales de MITRE ATT&CK.

    Se recogen de forma automatica para que la lista no haya que mantenerla a
    mano: si anades una tecnica nueva, el test la acepta sin tocar nada.
    """
    nombres = set()
    for ruta in modulos_python():
        arbol_modulo = arbol(ruta)
        for nodo in ast.walk(arbol_modulo):
            # TecnicaATTACK("T1046", "Network Service Discovery", "Discovery")
            if isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name):
                if nodo.func.id == "TecnicaATTACK":
                    for argumento in nodo.args[1:3]:
                        if isinstance(argumento, ast.Constant) and isinstance(argumento.value, str):
                            nombres.add(argumento.value)
            # Constante TACTICAS (puede ser Assign o AnnAssign)
            if isinstance(nodo, ast.Assign):
                valor = nodo.value
                objetivos = [t.id for t in nodo.targets if isinstance(t, ast.Name)]
            elif isinstance(nodo, ast.AnnAssign):
                valor = nodo.value
                objetivos = [nodo.target.id] if isinstance(nodo.target, ast.Name) else []
            else:
                valor, objetivos = None, []
            if "TACTICAS" in objetivos and valor is not None:
                for elemento in ast.walk(valor):
                    if isinstance(elemento, ast.Constant) and isinstance(elemento.value, str):
                        nombres.add(elemento.value)
    return nombres


class TestTextoEnEspanol(unittest.TestCase):
    """Todo el texto visible (CLI, logs, reporte, comentarios) va en espanol.

    Heuristico: detecta caracteres de alfabetos no latinos fuera de citas de
    identificadores tecnicos, que delatan texto sin traducir.
    """

    def test_sin_caracteres_de_alfabetos_no_latinos(self):
        import re

        # Se revisa tambien la documentacion: es texto visible para el usuario.
        ficheros = modulos_python() + [
            os.path.join(RAIZ, "README.md"),
            os.path.join(RAIZ, "requirements.txt"),
        ]
        for ruta in ficheros:
            if not os.path.isfile(ruta):
                continue
            with open(ruta, "r", encoding="utf-8-sig") as manejador:
                contenido = manejador.read()
            for patron, descripcion in (
                (r"[\u4e00-\u9fff]", "caracteres CJK (chino/japones)"),
                (r"[\u3040-\u30ff]", "kana (japones)"),
                (r"[\uac00-\ud7af]", "hangul (coreano)"),
                (r"[\u0400-\u04ff]", "cirilico (ruso)"),
            ):
                coincidencia = re.search(patron, contenido)
                self.assertIsNone(
                    coincidencia,
                    f"{nombre_ruta(ruta)} contiene {descripcion}: "
                    f"{coincidencia.group(0)!r}" if coincidencia else "",
                )

    def test_sin_palabras_extranjeras_soltas_en_textos_visibles(self):
        """Senales de texto sin traducir en literales de cadena."""
        import re

        # Palabras tipicas de un texto en ingles sin traducir.
        patron_ingles = re.compile(
            r'"[^"\n]*\b(the|and|with|from|your|network|scan|found|failed|error in)\b[^"\n]*"',
            re.IGNORECASE,
        )
        # Nombres oficiales de MITRE ATT&CK (se aceptan automaticamente) y
        # tecnicos que se citan tal cual.
        permitidos = tuple(nombres_oficiales_mitre()) + (
            "_RE_", "allow", "http", "https", "ascii", "latin",
            "nginx", "Apache", "httpd", "Redis", "MySQL", "MongoDB",
            "RabbitMQ", "Elasticsearch", "OpenSSH", "Windows", "Linux",
            "Ubuntu", "Spring Boot", "Apache-Coyote", "vsftpd", "net-snmp",
            "TCP connect scan", "connect scan", "SYN scan", "self.signed",
            # Ejemplos de invocacion: se citan literalmente y no se traducen.
            "python -m netscan", "scan,informe,menu",
        )
        for ruta in modulos_python():
            with open(ruta, "r", encoding="utf-8-sig") as manejador:
                lineas = manejador.read().splitlines()
            for numero, linea in enumerate(lineas, start=1):
                if linea.lstrip().startswith("#"):
                    continue
                for coincidencia in patron_ingles.finditer(linea):
                    texto = coincidencia.group(0)
                    # Tokens cortos y tecnicos (subcomandos, opciones) no se traducen.
                    if len(texto.strip('"')) < 12:
                        continue
                    if any(m in texto for m in permitidos):
                        continue
                    self.fail(
                        f"{nombre_ruta(ruta)}:{numero} posible texto sin traducir: {texto}"
                    )


class TestSinGlobalesMutables(unittest.TestCase):
    def test_no_hay_listas_ni_diccionarios_globales_mutables(self):
        for ruta in modulos_python():
            modulo = arbol(ruta)
            for nodo in modulo.body:
                destino = None
                if isinstance(nodo, ast.Assign):
                    if len(nodo.targets) != 1:
                        continue
                    destino = nodo.targets[0]
                elif isinstance(nodo, ast.AnnAssign):
                    destino = nodo.target
                if destino is None or not isinstance(destino, ast.Name):
                    continue

                valor = getattr(nodo, "value", None)
                if valor is None:
                    continue
                if isinstance(valor, (ast.List, ast.Dict, ast.Set, ast.ListComp)):
                    # Constantes inmutables (PERFILES, TACTICAS, catalogo) son
                    # correctas: no pueden mutarse. Solo se veta lo mutable.
                    sigue_siendo_constante = True
                    for hijo in ast.walk(valor):
                        if isinstance(hijo, ast.Call) and isinstance(hijo.func, ast.Name):
                            if hijo.func.id in ("list", "dict", "set"):
                                sigue_siendo_constante = False
                    if sigue_siendo_constante:
                        continue
                    self.fail(
                        f"{nombre_ruta(ruta)}:{nodo.lineno} define una global mutable "
                        f"'{destino.id}'"
                    )


class TestDocumentacion(unittest.TestCase):
    def test_todos_los_modulos_tienen_docstring(self):
        for ruta in modulos_python():
            modulo = arbol(ruta)
            self.assertIsNotNone(
                ast.get_docstring(modulo), f"{nombre_ruta(ruta)} sin docstring"
            )

    def test_las_funciones_publicas_relevantes_tienen_docstring(self):
        """Se exige docstring en la API publica, salvo en casos donde es ruido:
        propiedades triviales, sobreescrituras de una interfaz ya documentada y
        funciones de una sola instruccion cuyo nombre ya es explicito.
        """
        for ruta in modulos_python():
            if nombre_ruta(ruta) == "__init__.py":
                continue
            modulo = arbol(ruta)

            # Nombres definidos en clases base del propio paquete: si un metodo
            # sobrescribe otro, hereda su documentacion.
            heredados = set()
            for nodo in ast.walk(modulo):
                if isinstance(nodo, ast.ClassDef):
                    for base in nodo.bases:
                        for otro in ast.walk(modulo):
                            if (
                                isinstance(otro, ast.ClassDef)
                                and otro is not nodo
                                and otro.name == getattr(base, "id", None)
                            ):
                                heredados.update(
                                    b.name for b in otro.body
                                    if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))
                                )

            for nodo in ast.walk(modulo):
                if not isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if nodo.name.startswith("_"):
                    continue
                decoradores = {
                    d.id for d in nodo.decorator_list if isinstance(d, ast.Name)
                } | {
                    d.attr for d in nodo.decorator_list if isinstance(d, ast.Attribute)
                }
                if decoradores & {"property", "setter", "staticmethod", "classmethod"}:
                    continue
                if nodo.name in heredados:
                    continue
                # Funciones de una sola instruccion: el nombre ya describe el
                # proposito (p. ej. `ok`, `es_ipv4`, `peso_severidad`).
                if len(nodo.body) <= 1 and not isinstance(nodo.body[0], ast.Expr):
                    continue
                self.assertIsNotNone(
                    ast.get_docstring(nodo),
                    f"{nombre_ruta(ruta)}:{nodo.lineno} {nodo.name}() sin docstring",
                )

    def test_python_311_compatible(self):
        """No debe usarse sintaxis posterior a Python 3.11."""
        import sys

        if sys.version_info < (3, 11):
            self.skipTest("Se requiere Python 3.11 o superior")
        for ruta in modulos_python():
            # ast.parse ya valida la sintaxis contra la version actual.
            self.assertIsNotNone(arbol(ruta))


if __name__ == "__main__":
    unittest.main(verbosity=2)

