"""Country-aware ePDG egress coordination.

The control plane never edits host routes from its container namespace.  Instead it publishes a
small desired-state document under the shared data directory.  The host-side
``mdd-sim-gateway-orchestrator`` resolves each line's ePDG and owns the per-country sing-box TUN + /32
routes.  Engine startup waits for the corresponding line to become ready, preventing an IKE
attempt from leaking through the wrong country's default route.
"""
from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from copy import deepcopy

from . import config as cfg

_HERE = os.path.dirname(__file__)
_MCC_PATH = os.path.join(_HERE, "mcc_country.json")
_ORCH_DIR = os.path.join(cfg.DATA_DIR, "orchestrator")
_DESIRED = os.path.join(_ORCH_DIR, "desired.json")
_STATUS = os.path.join(_ORCH_DIR, "proxy-status.json")
_RESELECT = os.path.join(_ORCH_DIR, "exit-reselect.json")
_STALLED = os.path.join(_ORCH_DIR, "exit-stalled.json")
# A line healthy at least this long has proved its exit node can carry IMS.
RESELECT_MIN_STABLE_SECONDS = float(os.environ.get("MDD_EXIT_RESELECT_MIN_STABLE", "600"))


class EgressError(RuntimeError):
    pass


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EgressError("SOCKS5 proxy closed the UDP negotiation")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def test_udp_proxy(host: str, port: int, timeout: float = 8.0,
                   username: str = "", password: str = "") -> int:
    """Send one DNS query through a SOCKS5 UDP ASSOCIATE and return latency in ms.

    Country exits expose a loopback/bridge-only SOCKS5 listener. Testing that listener checks
    the complete configured outbound, including the UDP path VoWiFi IKE actually requires.
    """
    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as stream:
            stream.settimeout(timeout)
            methods = b"\x00\x02" if username or password else b"\x00"
            stream.sendall(b"\x05" + bytes([len(methods)]) + methods)
            method = _recv_exact(stream, 2)
            if method == b"\x05\x02":
                user, secret = username.encode(), password.encode()
                if not user or len(user) > 255 or len(secret) > 255:
                    raise EgressError("SOCKS5 username or password is invalid")
                stream.sendall(b"\x01" + bytes([len(user)]) + user
                               + bytes([len(secret)]) + secret)
                if _recv_exact(stream, 2) != b"\x01\x00":
                    raise EgressError("SOCKS5 username or password was rejected")
            elif method != b"\x05\x00":
                raise EgressError("SOCKS5 proxy rejected UDP test negotiation")
            stream.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            head = _recv_exact(stream, 4)
            if head[:2] != b"\x05\x00":
                raise EgressError(f"SOCKS5 proxy rejected UDP associate (code {head[1]})")
            atyp = head[3]
            if atyp == 1:
                relay_host = socket.inet_ntoa(_recv_exact(stream, 4))
            elif atyp == 3:
                relay_host = _recv_exact(stream, _recv_exact(stream, 1)[0]).decode("ascii")
            elif atyp == 4:
                relay_host = socket.inet_ntop(socket.AF_INET6, _recv_exact(stream, 16))
            else:
                raise EgressError("SOCKS5 proxy returned an invalid UDP relay address")
            relay_port = struct.unpack("!H", _recv_exact(stream, 2))[0]
            if relay_host in {"0.0.0.0", "::"}:
                relay_host = host

            query_id = os.urandom(2)
            # A cloudflare.com A query with recursion desired.
            dns = query_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                + b"\x0acloudflare\x03com\x00\x00\x01\x00\x01"
            packet = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") \
                + struct.pack("!H", 53) + dns
            family = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as udp:
                udp.settimeout(timeout)
                udp.sendto(packet, (relay_host, relay_port))
                response, _ = udp.recvfrom(4096)
            if len(response) < 22 or response[0:3] != b"\x00\x00\x00":
                raise EgressError("SOCKS5 proxy returned an invalid UDP response")
            # Skip the variable SOCKS destination header before checking the DNS transaction.
            response_atyp = response[3]
            offset = 4 + (4 if response_atyp == 1 else 16 if response_atyp == 4
                          else 1 + response[4] if response_atyp == 3 else -100) + 2
            if offset < 6 or response[offset:offset + 2] != query_id \
                    or not (response[offset + 2] & 0x80):
                raise EgressError("UDP DNS response did not match the test request")
    except EgressError:
        raise
    except (OSError, ValueError, struct.error) as exc:
        raise EgressError(f"UDP test failed: {exc}") from exc
    return max(1, round((time.monotonic() - started) * 1000))


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _write_private_json(path: Path, value: dict):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _process_detail(process: subprocess.Popen | None, limit: int = 300) -> str:
    """Whatever the test proxy printed before giving up, trimmed to one readable line."""
    if not process or not process.stderr:
        return ""
    try:
        text = process.stderr.read() or ""
    except (OSError, ValueError):
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:limit]


def _wait_tcp(port: int, process: subprocess.Popen, timeout: float = 4.0, what: str = "proxy"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            # The reason the process printed is the whole diagnosis; discarding it left the
            # operator with a generic failure for a node their other clients accept.
            detail = _process_detail(process)
            raise EgressError(f"{what} exited during startup"
                              + (f": {detail}" if detail else ""))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.08)
    raise EgressError(f"{what} did not become ready")


def _stop_process(process: subprocess.Popen | None):
    if not process or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _config_error(summary: str, completed) -> str:
    """Attach the checker's own complaint; it names the field an operator must fix."""
    text = ((completed.stderr or "") + "\n" + (completed.stdout or "")).strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    detail = " | ".join(lines[-2:])[:300]
    return f"{summary}: {detail}" if detail else summary


def _orchestrator_module():
    path = Path(__file__).resolve().parents[2] / "host" / "mdd_orchestrator.py"
    spec = importlib.util.spec_from_file_location("mdd_proxy_test_orchestrator", path)
    if not spec or not spec.loader:
        raise EgressError("proxy protocol support is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def describe_proxy_profile(profile: dict) -> dict:
    """Summarize how the gateway understood a pasted node, with no secret in the result.

    "It works in my other client" is only answerable by showing what this gateway parsed:
    a missing obfs or an SNI read from the wrong parameter is invisible otherwise. Server
    host, ports, passwords, UUIDs and keys are deliberately absent — only whether they are
    present, and the switches that decide whether the node can carry IKE at all.
    """
    kind = str(profile.get("type") or "").lower()
    if kind == "socks5":
        return {"protocol": "socks5", "udp_capable": True}
    value = str(profile.get("value") or "").strip()
    if not value:
        return {"error": "node share link is empty"}
    try:
        helper = _orchestrator_module()
        if value.startswith("{") or value.split("://", 1)[0].lower() in ("socks", "socks5"):
            outbound = helper.parse_manual_outbound(value, "describe")
            node = {}
        else:
            node = helper.parse_share_link(value)
            outbound = helper.clash_outbound(node, "describe")
    except (ValueError, EgressError) as exc:
        return {"error": str(exc)}
    tls = outbound.get("tls") or {}
    summary = {
        "protocol": str(outbound.get("type") or ""),
        "transport": str(node.get("network") or "tcp") if node else "",
        "tls": bool(tls.get("enabled")),
        "sni": str(tls.get("server_name") or ""),
        "alpn": list(tls.get("alpn") or []),
        "skip_cert_verify": bool(tls.get("insecure")),
        "reality": bool((tls.get("reality") or {}).get("enabled")),
        "utls_fingerprint": str((tls.get("utls") or {}).get("fingerprint") or ""),
        "obfs": str((outbound.get("obfs") or {}).get("type") or ""),
        "obfs_password_set": bool((outbound.get("obfs") or {}).get("password")),
        "flow": str(outbound.get("flow") or ""),
        "udp_capable": helper.outbound_supports_udp(outbound),
    }
    return {key: value for key, value in summary.items() if value not in ("", [], False)} \
        | {"udp_capable": summary["udp_capable"], "protocol": summary["protocol"]}


def test_proxy_profile(profile: dict, timeout: float = 8.0) -> int:
    """Test a node/SOCKS5 profile without assigning it to or changing a country exit."""
    kind = str(profile.get("type") or "").lower()
    if kind == "socks5":
        host = str(profile.get("server") or "").strip()
        port = int(profile.get("port") or 1080)
        if not host or not 0 < port <= 65535:
            raise EgressError("SOCKS5 server or port is invalid")
        return test_udp_proxy(host, port, timeout, str(profile.get("username") or ""),
                              str(profile.get("password") or ""))
    if kind != "node":
        raise EgressError("only individual nodes and SOCKS5 proxies can be tested here")

    value = str(profile.get("value") or "").strip()
    if not value:
        raise EgressError("node share link is empty")
    singbox = shutil.which(os.environ.get("MDD_SINGBOX_BIN", "sing-box"))
    if not singbox:
        raise EgressError("sing-box executable not found")
    helper = _orchestrator_module()
    node = helper.parse_share_link(value) if value.lower().startswith("vless://") else None
    xhttp = bool(node and str(node.get("network") or "").lower() == "xhttp")
    local_port, bridge_port = _free_loopback_port(), _free_loopback_port()
    if xhttp:
        outbound = {"type": "socks", "tag": "test-out", "version": "5",
                    "server": "127.0.0.1", "server_port": bridge_port}
    else:
        outbound = (helper.clash_outbound(node, "test-out") if node
                    else helper.parse_manual_outbound(value, "test-out"))
    if not helper.outbound_supports_udp(outbound):
        raise EgressError("this node protocol does not support UDP")

    sing_config = {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "test-in", "listen": "127.0.0.1",
                      "listen_port": local_port}],
        "outbounds": [outbound],
        "route": {"rules": [{"inbound": ["test-in"], "outbound": "test-out"}],
                  "auto_detect_interface": True},
    }
    sing_process = xray_process = None
    with tempfile.TemporaryDirectory(prefix="mdd-proxy-test-") as directory:
        root = Path(directory)
        sing_path = root / "sing-box.json"
        _write_private_json(sing_path, sing_config)
        check = subprocess.run([singbox, "check", "-c", str(sing_path)], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        if check.returncode:
            raise EgressError(_config_error("node configuration is invalid", check))
        try:
            if xhttp:
                xray = shutil.which(os.environ.get("MDD_XRAY_BIN", "xray"))
                if not xray:
                    raise EgressError("Xray-core executable not found for XHTTP node")
                xray_config = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": bridge_port,
                                  "protocol": "socks", "tag": "test-in",
                                  "settings": {"auth": "noauth", "udp": True,
                                               "ip": "127.0.0.1"}}],
                    "outbounds": [helper.xray_xhttp_outbound(node, "test-out")],
                    "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field",
                                "inboundTag": ["test-in"], "outboundTag": "test-out"}]},
                }
                xray_path = root / "xray.json"
                _write_private_json(xray_path, xray_config)
                xcheck = subprocess.run([xray, "run", "-test", "-config", str(xray_path)],
                                        text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=8)
                if xcheck.returncode:
                    raise EgressError(
                        _config_error("XHTTP node configuration is invalid", xcheck))
                xray_process = subprocess.Popen([xray, "run", "-config", str(xray_path)],
                                                stdout=subprocess.DEVNULL,
                                                stderr=subprocess.PIPE, text=True)
                _wait_tcp(bridge_port, xray_process, what="Xray-core")
            sing_process = subprocess.Popen([singbox, "run", "-c", str(sing_path)],
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE, text=True)
            _wait_tcp(local_port, sing_process, what="sing-box")
            try:
                return test_udp_proxy("127.0.0.1", local_port, timeout)
            except EgressError as exc:
                # The proxy is up but the node did not carry the probe. Whatever sing-box
                # logged while trying (handshake refused, auth rejected, no activity) is
                # the difference between "your node is wrong" and "we built it wrong".
                _stop_process(sing_process)
                detail = _process_detail(sing_process)
                raise EgressError(f"{exc}" + (f" — {detail}" if detail else "")) from exc
        finally:
            _stop_process(sing_process)
            _stop_process(xray_process)


def _atomic_json(path: str, value: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _mcc_map() -> dict[str, str]:
    return _read_json(_MCC_PATH)


def normalize_country(value: str | None) -> str:
    value = str(value or "").strip().lower().replace("_", "-")
    # Accept en-GB / zh_US style locale values but store ISO-3166 alpha-2 only.
    if "-" in value:
        value = value.rsplit("-", 1)[-1]
    return value if len(value) == 2 and value.isalpha() else ""


def country_for_mcc(mcc: str | int | None) -> str:
    return normalize_country(_mcc_map().get(str(mcc or "").zfill(3)))


def line_country(inst: dict) -> str:
    """Per-line override wins; otherwise infer the SIM home country from its MCC."""
    return normalize_country(inst.get("proxy_country")) or country_for_mcc(inst.get("mcc"))


def epdg_for(inst: dict) -> str:
    if inst.get("epdg"):
        return str(inst["epdg"]).strip()
    mcc = str(inst.get("mcc") or "").zfill(3)
    mnc = str(inst.get("mnc") or "").zfill(3)
    if not mcc.strip("0") or not mnc.strip("0"):
        return ""
    return f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"


def desired_document(instances: list[dict], settings: dict) -> dict:
    proxy = deepcopy(settings.get("proxy") or {})
    lines = []
    for inst in instances:
        lines.append({
            "id": str(inst.get("id", "")),
            "name": inst.get("name", ""),
            "enabled": bool(inst.get("enabled", True)),
            "mcc": str(inst.get("mcc", "")),
            "mnc": str(inst.get("mnc", "")),
            "country": line_country(inst),
            "epdg": epdg_for(inst),
        })
    return {"version": 1, "updated_at": int(time.time()), "proxy": proxy,
            "hardware": deepcopy(settings.get("hardware") or {}), "lines": lines}


def publish(instances: list[dict] | None = None, settings: dict | None = None) -> dict:
    instances = instances if instances is not None else cfg.list_instances()
    settings = settings if settings is not None else cfg.get_settings()
    document = desired_document(instances, settings)
    _atomic_json(_DESIRED, document)
    return document


def status() -> dict:
    return _read_json(_STATUS)


def request_reselect(inst: dict, reason: str, stable_for: float = 0.0) -> str:
    """Ask the host to move this SIM's country exit to a different node.

    Raised when the control plane gives up on a line. A line that cannot register is the only
    reliable evidence that an exit is unusable for VoWiFi: the ePDG tunnel can be established
    over a path on which SIP then goes unanswered, so no latency probe would catch it. The
    orchestrator owns sing-box and performs the change; this only records the request.

    ``stable_for`` is how long the line was healthy before it broke. Past a threshold the exit
    has demonstrably carried IMS, so the failure belongs to something else — a carrier-side
    problem, or a rekey a marginal path failed to survive. Moving the exit then costs another
    tunnel teardown, changes nothing, and evicts a node the operator may have pinned.

    Returns the country whose exit was asked to move, or "" when there is nothing to ask.
    """
    if stable_for >= RESELECT_MIN_STABLE_SECONDS:
        return ""
    country = line_country(inst)
    current = (status().get("exits") or {}).get(country) or {}
    # A locked exit is a deliberate operator choice — including while it is failing — and a
    # country routed direct has no node to move. A "preferred" pin still allows the move: the
    # host applies the preference when it picks the replacement. The orchestrator enforces
    # this too; skipping here keeps the file quiet.
    if not country or current.get("selection") == "manual" or current.get("mode") == "direct":
        return ""
    document = _read_json(_RESELECT)
    countries = document.get("countries")
    if not isinstance(countries, dict):
        countries = {}
    countries[country] = {"ts": time.time(), "reason": reason,
                          # The node that was in use when the line failed, so the orchestrator
                          # can put it in a cooldown instead of picking it again immediately.
                          "node": str(current.get("node") or ""),
                          "line": str(inst.get("id") or "")}
    _atomic_json(_RESELECT, {"version": 1, "countries": countries})
    return country


def report_stalled_exit(country: str, node: str, reason: str, line: str) -> bool:
    """Tell the host this country's exit is holding connections that carry nothing.

    Deliberately weaker than request_reselect: that one says "this node is bad, move off it",
    which tears down every tunnel on it. This says "the node may well be fine — but the
    sessions pinned to it are dead, close them so the next packet dials again".

    It exists because a stalled session cannot time out on its own. sing-box retires a UDP
    session on an IDLE timer, and a line rebuilding its tunnel retransmits IKE every few
    seconds; each retransmit refreshes the timer on the very session whose outbound already
    died. The line then retries forever against a connection that can never carry a packet.

    The caller must have attributed the failure to the exit AND established that no sibling
    line is registered over it, so this never disturbs a working tunnel. Returns True when a
    report was written.
    """
    country = str(country or "").strip().lower()
    if not country:
        return False
    document = _read_json(_STALLED)
    countries = document.get("countries")
    if not isinstance(countries, dict):
        countries = {}
    countries[country] = {"ts": time.time(), "reason": str(reason or ""),
                          "node": str(node or ""), "line": str(line or "")}
    _atomic_json(_STALLED, {"version": 1, "countries": countries})
    return True


def ensure_line(inst: dict, settings: dict, timeout: float = 18.0) -> dict:
    """Publish desired state and wait until the host confirms the line's ePDG route.

    Proxy routing is opt-in globally.  With it enabled, missing/unhealthy exits fail closed unless
    the country entry explicitly selects ``direct``.  That is intentional: silently using the
    host default route can expose the wrong geography to an operator ePDG.
    """
    proxy = settings.get("proxy") or {}
    publish(settings=settings)
    if not proxy.get("enabled", False):
        return {"ready": True, "mode": "legacy"}
    country = line_country(inst)
    if not country:
        raise EgressError("cannot determine SIM country from MCC; set a line country override")
    exits = proxy.get("exits") or {}
    exit_cfg = exits.get(country) or {}
    if not exit_cfg.get("enabled", False):
        raise EgressError(f"no enabled proxy exit configured for country {country.upper()}")
    deadline = time.monotonic() + max(1.0, timeout)
    iid = str(inst.get("id", ""))
    last = {}
    while time.monotonic() < deadline:
        state = status()
        last = (state.get("lines") or {}).get(iid) or {}
        if last.get("ready"):
            return last
        # A terminal config error should be returned immediately; DNS/probe errors may recover.
        if last.get("terminal"):
            break
        time.sleep(0.4)
    reason = last.get("error") or "country egress route was not ready before engine startup"
    raise EgressError(f"{country.upper()} exit unavailable: {reason}")
