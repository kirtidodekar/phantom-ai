"""
Scapy-backed packet capture.

DESIGN CONTRACT
  * Capture runs on a background thread and NEVER blocks the FastAPI loop.
  * Packets are pushed onto a BOUNDED queue. Under overload the oldest entries
    are dropped and the loss is COUNTED and REPORTED - never silently hidden.
  * If the capture backend is unavailable (missing Npcap/libpcap, no
    permission, bad interface) the monitor refuses to start and returns a
    precise reason. It NEVER fabricates packets to look healthy.
  * Only observation is performed. No packet is ever transmitted.
"""

from __future__ import annotations

import hashlib
import platform
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import PacketMetadata

_PROTO_NUMBERS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_TCP_FLAG_MAP = [
    (0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
    (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C"),
]
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                     "127.", "169.254.")


def scapy_available() -> tuple:
    """Returns (available, detail) without raising if Scapy is absent."""
    try:
        import scapy  # noqa: F401
        from scapy.all import conf  # noqa: F401
        return True, "scapy_importable"
    except Exception as error:  # pragma: no cover - environment dependent
        return False, f"scapy_import_failed: {type(error).__name__}"


def capture_backend_status() -> Dict[str, Any]:
    """
    Probes whether real capture is actually possible on this host.

    This is the honest-status function the dashboard depends on: it reports
    exactly what is missing instead of pretending capture will work.
    """
    system = platform.system()
    available, detail = scapy_available()

    status: Dict[str, Any] = {
        "platform": system,
        "scapy_available": available,
        "scapy_detail": detail,
        "driver_available": False,
        "driver_name": "Npcap/WinPcap" if system == "Windows" else "libpcap",
        "capture_possible": False,
        "reason": None,
        "remediation": None,
    }

    if not available:
        status["reason"] = "scapy_not_installed"
        status["remediation"] = "Install Scapy: pip install scapy"
        return status

    if system == "Windows":
        import os
        driver = (
            os.path.exists(r"C:\Windows\System32\Npcap")
            or os.path.exists(r"C:\Windows\System32\wpcap.dll")
            or os.path.exists(r"C:\Windows\SysWOW64\wpcap.dll")
        )
        status["driver_available"] = driver
        if not driver:
            status["reason"] = "npcap_missing"
            status["remediation"] = (
                "Install Npcap from https://npcap.com (enable WinPcap-compatible "
                "mode), then run the backend as Administrator."
            )
            return status
    else:
        status["driver_available"] = True

    status["capture_possible"] = True
    return status


def list_interfaces() -> List[Dict[str, Any]]:
    """Enumerates capture-capable interfaces, or an empty list if unavailable."""
    available, _ = scapy_available()
    if not available:
        return []

    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            adapters = []
            for nic in get_windows_if_list():
                guid = nic.get("guid")
                # Capture requires the NPF device path, not the friendly name.
                npf_name = f"\\Device\\NPF_{guid}" if guid else nic.get("name")
                adapters.append({
                    "name": npf_name,
                    "friendly_name": nic.get("name"),
                    "description": nic.get("description"),
                    "guid": guid,
                    "ips": [ip for ip in (nic.get("ips") or []) if ":" not in str(ip)],
                })
            return adapters
        from scapy.all import get_if_list, get_if_addr
        result = []
        for name in get_if_list():
            try:
                addr = get_if_addr(name)
            except Exception:
                addr = None
            result.append({"name": name, "description": name, "ips": [addr] if addr else []})
        return result
    except Exception:
        return []


def resolve_interface(requested: str) -> Optional[str]:
    """Resolves 'auto' to the default interface, or validates an explicit name."""
    available, _ = scapy_available()
    if not available:
        return None

    if requested and requested.lower() != "auto":
        # An NPF device path is already a valid capture target. Scapy's
        # conf.iface and our own list_interfaces() both emit this form, so it
        # must be accepted without a friendly-name lookup.
        if requested.startswith("\\Device\\NPF_"):
            return requested

        # Otherwise match against every identifier we expose for an adapter.
        for nic in list_interfaces():
            candidates = {
                str(nic.get("name")),
                str(nic.get("friendly_name")),
                str(nic.get("description")),
                str(nic.get("guid")),
            }
            if requested in candidates:
                return str(nic.get("name"))

        # No adapter inventory available (non-Windows fallback): trust the caller.
        return requested if not list_interfaces() else None

    try:
        from scapy.all import conf
        return str(conf.iface) if conf.iface else None
    except Exception:
        return None


def _connection_id(src: str, dst: str, sport, dport, proto: str) -> str:
    """Stable 5-tuple identifier, direction-normalized."""
    a, b = f"{src}:{sport or 0}", f"{dst}:{dport or 0}"
    low, high = sorted([a, b])
    return hashlib.sha1(f"{low}|{high}|{proto}".encode()).hexdigest()[:16]


def _classify_direction(src: str, dst: str) -> str:
    src_private = str(src).startswith(_PRIVATE_PREFIXES)
    dst_private = str(dst).startswith(_PRIVATE_PREFIXES)
    if src_private and dst_private:
        return "internal"
    if src_private and not dst_private:
        return "outbound"
    if dst_private and not src_private:
        return "inbound"
    return "unknown"


def _decode_tcp_flags(flag_value: int) -> str:
    try:
        value = int(flag_value)
    except (TypeError, ValueError):
        return ""
    return "".join(label for bit, label in _TCP_FLAG_MAP if value & bit)


def extract_packet_metadata(packet, interface: str) -> Optional[PacketMetadata]:
    """
    Converts a captured Scapy packet into header-only metadata.

    Returns None for non-IP frames (ARP, pure L2) which carry no IP telemetry.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
    except Exception:
        return None

    ip_layer = None
    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
    if ip_layer is None:
        return None

    src_ip = str(getattr(ip_layer, "src", ""))
    dst_ip = str(getattr(ip_layer, "dst", ""))
    if not src_ip or not dst_ip:
        return None

    proto_num = getattr(ip_layer, "proto", None) or getattr(ip_layer, "nh", None)
    protocol = _PROTO_NUMBERS.get(proto_num, str(proto_num or "IP"))

    sport = dport = None
    tcp_flags = ""
    if packet.haslayer(TCP):
        protocol = "TCP"
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
        tcp_flags = _decode_tcp_flags(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return PacketMetadata(
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=sport,
        destination_port=dport,
        protocol=protocol,
        packet_size=int(len(packet)),
        tcp_flags=tcp_flags,
        interface=interface,
        direction=_classify_direction(src_ip, dst_ip),
        connection_id=_connection_id(src_ip, dst_ip, sport, dport, protocol),
        is_simulated=False,
    )


class PacketCaptureEngine:
    """Owns the Scapy sniffer thread and the bounded hand-off queue."""

    def __init__(self, queue_size: int = 20000):
        self._queue: "queue.Queue" = queue.Queue(maxsize=max(100, queue_size))
        self._sniffer = None
        self._lock = threading.Lock()
        self._running = False
        self.interface: Optional[str] = None
        self.capture_filter: str = ""
        self.started_at: Optional[float] = None
        self.packets_captured = 0
        self.packets_dropped = 0
        self.non_ip_frames = 0
        self.last_error: Optional[str] = None

    # ---------------- lifecycle ----------------

    def start(self, interface: str, capture_filter: str = "") -> Dict[str, Any]:
        """Starts capture. Raises RuntimeError with a precise reason on failure."""
        with self._lock:
            if self._running:
                return {"status": "ALREADY_RUNNING", "interface": self.interface}

            backend = capture_backend_status()
            if not backend["capture_possible"]:
                self.last_error = backend["reason"]
                raise RuntimeError(
                    f"capture_unavailable:{backend['reason']}: {backend['remediation']}"
                )

            resolved = resolve_interface(interface)
            if not resolved:
                self.last_error = "interface_unavailable"
                raise RuntimeError(f"interface_unavailable: '{interface}' could not be resolved")

            try:
                from scapy.all import AsyncSniffer
                sniffer = AsyncSniffer(
                    iface=resolved,
                    filter=capture_filter or None,
                    prn=self._on_packet,
                    store=False,
                )
                sniffer.start()
            except PermissionError as error:
                self.last_error = "insufficient_permissions"
                raise RuntimeError(f"insufficient_permissions: {error}") from error
            except Exception as error:
                self.last_error = f"capture_start_failed: {type(error).__name__}"
                raise RuntimeError(f"capture_start_failed: {error}") from error

            self._sniffer = sniffer
            self._running = True
            self.interface = resolved
            self.capture_filter = capture_filter
            self.started_at = time.time()
            self.last_error = None
            return {"status": "STARTED", "interface": resolved, "filter": capture_filter}

    def stop(self) -> Dict[str, Any]:
        """Stops capture. Safe to call when already stopped."""
        with self._lock:
            if not self._running:
                return {"status": "ALREADY_STOPPED"}
            try:
                if self._sniffer is not None:
                    self._sniffer.stop()
            except Exception as error:
                self.last_error = f"capture_stop_warning: {type(error).__name__}"
            finally:
                self._sniffer = None
                self._running = False
            return {"status": "STOPPED"}

    # ---------------- capture path ----------------

    def _on_packet(self, packet) -> None:
        """Sniffer callback. Kept deliberately cheap - no ML, no database."""
        meta = extract_packet_metadata(packet, self.interface or "unknown")
        if meta is None:
            self.non_ip_frames += 1
            return

        self.packets_captured += 1
        try:
            self._queue.put_nowait(meta)
        except queue.Full:
            # Bounded queue: shed the oldest record and count the loss.
            self.packets_dropped += 1
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(meta)
            except Exception:
                pass

    def drain(self, limit: int = 5000) -> List[PacketMetadata]:
        """Removes up to `limit` packets for downstream processing."""
        batch: List[PacketMetadata] = []
        for _ in range(max(1, limit)):
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    # ---------------- introspection ----------------

    @property
    def is_running(self) -> bool:
        if self._running and self._sniffer is not None:
            thread = getattr(self._sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                # The sniffer died underneath us - surface it instead of lying.
                self._running = False
                self.last_error = "capture_thread_died"
        return self._running

    def status(self) -> Dict[str, Any]:
        uptime = round(time.time() - self.started_at, 1) if self.started_at else 0.0
        return {
            "running": self.is_running,
            "interface": self.interface,
            "capture_filter": self.capture_filter,
            "uptime_seconds": uptime,
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "non_ip_frames": self.non_ip_frames,
            "queue_depth": self._queue.qsize(),
            "last_error": self.last_error,
        }
