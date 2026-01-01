"""Network discovery module for Leviathan."""

import asyncio
import socket
from typing import List, Dict, Any, Optional, Tuple
from ipaddress import ip_address, ip_network
import re

from ...core.module_base import AnalysisModule
from ...utils.logging import get_logger


class NetworkDiscoveryModule(AnalysisModule):
    """Module for discovering network services and hosts."""

    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }

    def __init__(self, config=None):
        super().__init__(config)
        self.logger = get_logger("leviathan.modules.discovery.network")

    @property
    def name(self) -> str:
        return "network_discovery"

    @property
    def description(self) -> str:
        return "Discovers network services and open ports on target hosts"

    async def analyze(self, target: Any) -> Dict[str, Any]:
        """Analyze target for network services."""
        if isinstance(target, str):
            # Try to parse as IP, network, or hostname
            try:
                if '/' in target:
                    # CIDR notation
                    network = ip_network(target, strict=False)
                    targets = [str(ip) for ip in network.hosts()]
                elif '-' in target:
                    # IP range (simple implementation)
                    targets = self._parse_ip_range(target)
                else:
                    # Single IP or hostname
                    ip_address(target)  # Validate
                    targets = [target]
            except ValueError:
                # Assume hostname
                targets = [target]
        elif isinstance(target, list):
            targets = target
        else:
            raise ValueError("Target must be IP, network, hostname, or list")

        # Get configuration
        ports = getattr(self.config, 'ports', list(self.COMMON_PORTS.keys())) if self.config else list(self.COMMON_PORTS.keys())
        timeout = getattr(self.config, 'timeout', 1.0) if self.config else 1.0
        max_concurrent = getattr(self.config, 'max_concurrent', 100) if self.config else 100

        self.logger.info(
            "Starting network discovery",
            targets=len(targets),
            ports=len(ports),
            timeout=timeout
        )

        # Perform port scanning
        results = await self._scan_network(targets, ports, timeout, max_concurrent)

        return {
            "targets_scanned": len(targets),
            "ports_scanned": len(ports),
            "open_ports": results,
            "services_found": self._identify_services(results)
        }

    async def _scan_network(
        self,
        targets: List[str],
        ports: List[int],
        timeout: float,
        max_concurrent: int
    ) -> List[Dict[str, Any]]:
        """Scan network for open ports."""
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = []

        for target in targets:
            for port in ports:
                tasks.append(self._scan_port(target, port, timeout, semaphore))

        # Execute all scans concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and collect successful results
        open_ports = []
        for result in results:
            if isinstance(result, dict):
                open_ports.append(result)
            elif isinstance(result, Exception):
                self.logger.debug("Scan failed", error=str(result))

        return open_ports

    async def _scan_port(
        self,
        target: str,
        port: int,
        timeout: float,
        semaphore: asyncio.Semaphore
    ) -> Optional[Dict[str, Any]]:
        """Scan a single port on a target."""
        async with semaphore:
            try:
                # Resolve hostname if needed
                try:
                    resolved_ip = socket.gethostbyname(target)
                except socket.gaierror:
                    resolved_ip = target

                # Create socket and attempt connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                loop = asyncio.get_event_loop()
                result = await loop.sock_connect(sock, (resolved_ip, port))

                # Connection successful
                service = self.COMMON_PORTS.get(port, "Unknown")
                sock.close()

                return {
                    "ip": resolved_ip,
                    "hostname": target if target != resolved_ip else None,
                    "port": port,
                    "service": service,
                    "state": "open"
                }

            except (socket.timeout, socket.error, OSError):
                # Port closed or unreachable
                return None

    def _parse_ip_range(self, ip_range: str) -> List[str]:
        """Parse IP range like 192.168.1.1-192.168.1.10."""
        # Simple implementation for consecutive IPs
        parts = ip_range.split('-')
        if len(parts) == 2:
            start_ip = parts[0].strip()
            end_ip = parts[1].strip()

            try:
                start_parts = list(map(int, start_ip.split('.')))
                end_parts = list(map(int, end_ip.split('.')))

                # Only handle simple case where only last octet differs
                if (start_parts[0] == end_parts[0] and
                    start_parts[1] == end_parts[1] and
                    start_parts[2] == end_parts[2]):
                    start_octet = start_parts[3]
                    end_octet = end_parts[3]

                    base = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}."
                    return [f"{base}{i}" for i in range(start_octet, end_octet + 1)]
            except (ValueError, IndexError):
                pass

        # Fallback to single IP
        return [ip_range]

    def _identify_services(self, open_ports: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group open ports by service type."""
        services = {}

        for port_info in open_ports:
            service = port_info["service"]
            if service not in services:
                services[service] = []
            services[service].append(port_info)

        return services