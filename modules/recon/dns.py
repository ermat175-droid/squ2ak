"""DNS-записи и ограниченная попытка передачи зоны."""

from __future__ import annotations

import ipaddress

from core.module_base import BaseModule
from utils import renderer
from utils.net import target_host


def bounded_transfer(messages, max_records: int = 4096):
    """Ограничиваем объём зоны до построения объекта dnspython."""
    count = 0
    for message in messages:
        count += sum(len(records) for records in message.answer)
        if count > max_records:
            raise ValueError("DNS zone exceeds 4096 record limit")
        yield message


class DNSModule(BaseModule):
    name = "dns"
    category = "recon"
    description = "Resolve A/AAAA/MX/TXT/NS records and attempt AXFR"
    options = {
        "target": {"default": None, "required": True, "description": "Target hostname"},
        "domain": {"default": "", "required": False, "description": "Domain override for DNS queries"},
        "timeout": {"default": 5.0, "required": False, "description": "DNS timeout in seconds"},
        "axfr": {"default": True, "required": False, "description": "Attempt zone transfer against up to three nameservers"},
    }

    def run(self) -> None:
        import dns.exception
        import dns.query
        import dns.resolver
        import dns.zone

        domain = target_host(self.get_option("domain") or self.get_option("target")).rstrip(".")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            renderer.print_warn("DNS records require a domain; set domain example.test")
            return
        timeout = float(self.get_option("timeout"))
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        rows = []
        nameservers: list[str] = []
        for record_type in ("A", "AAAA", "MX", "TXT", "NS"):
            try:
                answers = resolver.resolve(domain, record_type, lifetime=timeout)
                values = [answer.to_text() for answer in answers]
                for value in values:
                    rows.append((record_type, value))
                if values:
                    self.session.add_loot("dns", {"record_type": record_type, "records": values}, domain)
                if record_type == "NS":
                    nameservers = [value.rstrip(".") for value in values]
            except dns.exception.DNSException as exc:
                renderer.print_warn(f"{record_type}: {exc}")
        renderer.print_table(f"DNS records: {domain}", ("Type", "Value"), rows)
        axfr = self.get_option("axfr")
        if isinstance(axfr, str):
            axfr = axfr.lower() in {"1", "true", "yes", "on"}
        if not axfr:
            return
        for nameserver in nameservers[:3]:
            try:
                try:
                    addresses = resolver.resolve(nameserver, "A", lifetime=timeout)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    addresses = resolver.resolve(nameserver, "AAAA", lifetime=timeout)
                address = next(iter(addresses)).to_text()
                transfer = dns.query.xfr(address, domain, timeout=timeout, lifetime=timeout)
                zone = dns.zone.from_xfr(bounded_transfer(transfer))
                if zone is None:
                    continue
                records = [f"{name} {rdataset.to_text()}" for name, node in zone.nodes.items() for rdataset in node.rdatasets]
                source = f"dns://{nameserver}/{domain}"
                self.session.add_loot("dns_zone", records, source)
                self.session.add_finding("DNS zone transfer allowed", source, severity="medium", nameserver=nameserver)
                renderer.print_success(f"AXFR succeeded on {nameserver}: {len(records)} record sets")
            except (dns.exception.DNSException, OSError, ValueError, StopIteration) as exc:
                renderer.print_info(f"AXFR {nameserver}: {exc}")
