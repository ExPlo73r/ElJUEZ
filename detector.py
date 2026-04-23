import re

IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def detect(ioc: str) -> str:
    """Devuelve el tipo del IOC: ip, domain, url, md5, sha1, sha256, unknown."""
    ioc = ioc.strip()
    if URL_RE.match(ioc):
        return "url"
    if IPV4_RE.match(ioc):
        return "ip"
    if SHA256_RE.match(ioc):
        return "sha256"
    if SHA1_RE.match(ioc):
        return "sha1"
    if MD5_RE.match(ioc):
        return "md5"
    if DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


def load_iocs(filepath: str) -> list[dict]:
    """Lee un archivo de IOCs (uno por línea) y detecta su tipo."""
    results = []
    with open(filepath, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            ioc_type = detect(line)
            results.append({"ioc": line, "type": ioc_type})
    return results
