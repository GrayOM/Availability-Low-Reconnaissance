"""
collectors/port_collector.py
=============================
Port scanning using naabu (low-impact mode).
Returns data_source: "naabu" | "mock" | "missing"
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from models.schema import OpenPort, PortSummary, TargetContext
from utils.logger import get_logger
from utils.subprocess_runner import run_tool

logger = get_logger(__name__)

_DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,143,443,445,465,587,993,995,"
    "1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"
)

_PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp-submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 8888: "jupyter", 9200: "elasticsearch", 27017: "mongodb",
}


def _mock_open_ports(host: str) -> list:
    return [OpenPort(host=host, port=p, service=_PORT_SERVICE_MAP.get(p))
            for p in [80, 443, 22, 8080]]


def _parse_naabu_line(line: str) -> Optional[OpenPort]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        host = obj.get("ip") or obj.get("host", "")
        port = int(obj.get("port", 0))
        if host and port:
            return OpenPort(host=host, port=port, service=_PORT_SERVICE_MAP.get(port))
    except Exception:
        pass
    if ":" in line:
        parts = line.rsplit(":", 1)
        try:
            return OpenPort(host=parts[0], port=int(parts[1]),
                            service=_PORT_SERVICE_MAP.get(int(parts[1])))
        except Exception:
            pass
    return None


def collect_ports(ctx: TargetContext, allow_mock: bool = False):
    target = ctx.domain or ctx.ip or ctx.raw_input
    summary = PortSummary(target=target)

    tool_result = run_tool(
        "naabu",
        args=["-host", target, "-p", _DEFAULT_PORTS,
              "-rate", "100", "-retries", "1", "-timeout", "300",
              "-json", "-silent"],
        timeout=ctx.timeout + 120,
    )

    if tool_result.skipped:
        if not allow_mock:
            summary.data_source = "missing"
            return summary
        logger.warning("naabu unavailable — using MOCK data for %s", target)
        summary.open_ports = _mock_open_ports(target)
        summary.raw_output = "MOCK_DATA"
        summary.data_source = "mock"
    elif not tool_result.success:
        logger.error("naabu failed rc=%d", tool_result.returncode)
        summary.raw_output = tool_result.stderr
        summary.data_source = "error"
    else:
        raw = tool_result.stdout.strip()
        summary.raw_output = raw
        summary.data_source = "naabu"
        for line in raw.splitlines():
            p = _parse_naabu_line(line)
            if p:
                summary.open_ports.append(p)

    logger.info("Ports: %d open (source: %s)", len(summary.open_ports), summary.data_source)
    norm_file = Path(ctx.output_dir) / "ports_normalized.json"
    norm_file.write_text(json.dumps(
        {"data_source": summary.data_source,
         "open_ports": [p.model_dump() for p in summary.open_ports]}, indent=2))
    return summary
