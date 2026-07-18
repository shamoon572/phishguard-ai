"""
DNS resolution service.

Resolves A/AAAA/MX/NS records and flags patterns commonly seen with
phishing infrastructure: bare-IP hosting behind a URL that pretends to
be a domain, or a suspiciously small/absent NS footprint.
"""

import dns.resolver


def _resolve(hostname: str, record_type: str, resolver: dns.resolver.Resolver):
    try:
        answers = resolver.resolve(hostname, record_type)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def check_dns(hostname: str, timeout: int = 5) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    a_records = _resolve(hostname, "A", resolver)
    aaaa_records = _resolve(hostname, "AAAA", resolver)
    ns_records = _resolve(hostname, "NS", resolver)
    mx_records = _resolve(hostname, "MX", resolver)

    if not a_records and not aaaa_records:
        return {
            "status": "danger",
            "resolves": False,
            "message": "Domain does not resolve to any IP address.",
        }

    flags = []
    if not ns_records:
        flags.append("No nameserver (NS) records found.")

    status = "warning" if flags else "safe"

    return {
        "status": status,
        "resolves": True,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "ns_records": ns_records,
        "mx_records": mx_records,
        "flags": flags,
        "message": "DNS resolves normally." if not flags else "; ".join(flags),
    }
