"""IP-ga oid yordamchi funksiyalar."""
import ipaddress


# Aniq RFC1918 tarmoqlari (Python is_private dokumentatsiya IP'larni ham qaytaradi —
# biz buni xohlamaymiz, faqat haqiqiy ichki tarmoqni belgilamoqchimiz)
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_internal_ip(ip: str) -> bool:
    """Faqat haqiqiy ichki tarmoq (RFC1918 + loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
