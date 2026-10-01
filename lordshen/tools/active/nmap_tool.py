"""Nmap wrapper — deep service fingerprinting and scripting engine."""

import xml.etree.ElementTree as ET
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class NmapWrapper:
    """Wrapper for Nmap network scanner."""

    name: str = "nmap"
    binary: str = "nmap"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run nmap service/version scan.

        Args:
            target: IP address, hostname, or CIDR range.
            ports: Comma-separated port list or range.
            udp: Whether to also run UDP scan.
        """
        output_path = get_temp_output_path("nmap", "xml")
        ports = kwargs.get("ports", "")
        udp = kwargs.get("udp", False)

        cmd = ["nmap", "-sV", "-sC", "--script=banner"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.extend(["-oX", str(output_path), target])

        result = await run_tool(cmd, timeout=300)

        findings: list[ToolFinding] = []
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw)
            try:
                output_path.unlink()
            except OSError:
                pass

        # Optional UDP scan
        if udp:
            udp_output = get_temp_output_path("nmap_udp", "xml")
            udp_cmd = [
                "sudo", "nmap", "-sU", "--top-ports", "100",
                "-oX", str(udp_output), target,
            ]
            udp_result = await run_tool(udp_cmd, timeout=600)
            if udp_output.exists():
                udp_raw = udp_output.read_text(errors="replace")
                findings.extend(self.parse_output(udp_raw))
                try:
                    udp_output.unlink()
                except OSError:
                    pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse nmap XML output."""
        findings: list[ToolFinding] = []

        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return findings

        for host_elem in root.findall("host"):
            # Get host IP
            ip = ""
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is not None:
                ip = addr_elem.get("addr", "")

            # Get hostname
            hostname = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            display_host = hostname or ip

            # Get OS detection
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for osmatch in os_elem.findall("osmatch"):
                    os_name = osmatch.get("name", "")
                    accuracy = osmatch.get("accuracy", "")
                    if os_name:
                        findings.append(ToolFinding(
                            title=f"OS detected: {os_name} ({accuracy}% confidence)",
                            severity="info",
                            host=display_host,
                            tool_name=self.name,
                            evidence=f"OS: {os_name}, Accuracy: {accuracy}%",
                            extra={"type": "os_detection", "os": os_name, "accuracy": accuracy},
                        ))
                        break  # Only take best match

            # Get ports and services
            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""

                if state != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = ""
                product = ""
                version = ""
                extra_info = ""

                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extra_info = service_elem.get("extrainfo", "")

                title = f"Port {port_id}/{protocol}: {service_name}"
                if product:
                    title += f" ({product}"
                    if version:
                        title += f" {version}"
                    title += ")"

                # Check for NSE script output
                script_output: list[str] = []
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_out = script_elem.get("output", "")
                    if script_out:
                        script_output.append(f"{script_id}: {script_out[:200]}")

                severity = "info"
                # Flag potentially vulnerable versions
                if version and any(kw in product.lower() for kw in
                                   ["apache", "nginx", "openssh", "mysql", "postgresql"]):
                    severity = "info"  # Version detection only

                findings.append(ToolFinding(
                    title=title,
                    severity=severity,
                    host=display_host,
                    tool_name=self.name,
                    evidence="\n".join(script_output) if script_output else title,
                    extra={
                        "type": "service",
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extra_info": extra_info,
                        "scripts": script_output,
                    },
                ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("nmap")
