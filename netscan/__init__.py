"""NetAudit - auditoria de red defensiva basada en nmap.

Solo para redes con autorizacion escrita explicita. NetAudit descubre,
reconoce y evalua; no explota, no obtiene acceso y no escala privilegios.

Uso minimo:

    python -m netscan.cli scan --target 192.168.1.10 --autorizado
    python -m netscan.cli            # menu interactivo
"""

from __future__ import annotations

__version__ = "2.0.0"
__all__ = ["__version__"]
