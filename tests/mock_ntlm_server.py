"""
Mock HTTP server that simulates NTLM authentication endpoints.

Returns realistic NTLM Type 2 (Challenge) responses for testing NTLMEnum
without needing a real Windows/AD environment.
"""

import base64
import struct
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

# Simulated AD environment
DOMAIN_CONFIG = {
    "netbios_domain": "STEALTHSTRIKE",
    "netbios_computer": "YOURSERVER01",
    "dns_domain": "stealthstrike.local",
    "dns_computer": "yourserver01.stealthstrike.local",
    "dns_tree": "stealthstrike.local",
    "os_major": 10,
    "os_minor": 0,
    "os_build": 20348,
}

# Endpoints that return NTLM auth challenges
NTLM_ENDPOINTS = {
    "/owa/",
    "/ews/",
    "/EWS/Exchange.asmx",
    "/autodiscover/autodiscover.xml",
    "/mapi/nspi/",
    "/rpc/",
    "/certsrv/",
    "/internal-app/",
    "/secret-panel/admin/",
}

# Endpoints that return Basic auth (not NTLM)
BASIC_ENDPOINTS = {
    "/basic-auth/",
}

# Endpoints that return Negotiate (SPNEGO-wrapped NTLM)
NEGOTIATE_ENDPOINTS = {
    "/adfs/ls/wia",
    "/negotiate-auth/",
}

# HTML pages with links (for crawl testing)
PAGES = {
    "/": """<!DOCTYPE html>
<html>
<head><title>Corporate Intranet</title></head>
<body>
    <h1>Welcome to the Corporate Intranet</h1>
    <nav>
        <a href="/about/">About</a>
        <a href="/owa/">Outlook Web Access</a>
        <a href="/internal-app/">Internal Application</a>
        <a href="/docs/">Documentation</a>
        <a href="/basic-auth/">Basic Auth Area</a>
    </nav>
</body>
</html>""",
    "/about/": """<!DOCTYPE html>
<html>
<head><title>About</title></head>
<body>
    <h1>About Us</h1>
    <p>Internal corporate site.</p>
    <a href="/">Home</a>
    <a href="/secret-panel/admin/">Admin Panel</a>
    <a href="/adfs/ls/wia">SSO Login</a>
    <a href="/reports/dashboard/">Reports</a>
</body>
</html>""",
    "/docs/": """<!DOCTYPE html>
<html>
<head><title>Documentation</title></head>
<body>
    <h1>Docs</h1>
    <a href="/">Home</a>
    <a href="/certsrv/">Certificate Services</a>
    <a href="/negotiate-auth/">Negotiate Auth Test</a>
    <script>
        fetch('/api/health');
    </script>
</body>
</html>""",
    "/reports/dashboard/": """<!DOCTYPE html>
<html>
<head><title>Reports</title></head>
<body>
    <h1>Reports Dashboard</h1>
    <a href="/">Home</a>
    <a href="/ews/">Exchange Web Services</a>
</body>
</html>""",
}


def build_av_pair(av_id: int, value: str) -> bytes:
    encoded = value.encode("utf-16-le")
    return struct.pack("<HH", av_id, len(encoded)) + encoded


def build_challenge_message(config: dict) -> bytes:
    """Build a realistic NTLM Type 2 Challenge message."""
    from ntlmenum.ntlm import (
        NTLMSSP_NEGOTIATE_UNICODE,
        NTLMSSP_NEGOTIATE_NTLM,
        NTLMSSP_NEGOTIATE_TARGET_INFO,
        NTLMSSP_NEGOTIATE_VERSION,
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        NTLMSSP_REQUEST_TARGET,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
        NTLMSSP_NEGOTIATE_128,
        NTLMSSP_NEGOTIATE_56,
    )

    flags = (
        NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
    )

    # Build AV_PAIRs
    av_pairs = b""
    av_pairs += build_av_pair(0x0002, config["netbios_domain"])
    av_pairs += build_av_pair(0x0001, config["netbios_computer"])
    av_pairs += build_av_pair(0x0004, config["dns_domain"])
    av_pairs += build_av_pair(0x0003, config["dns_computer"])
    av_pairs += build_av_pair(0x0005, config["dns_tree"])

    # Timestamp
    now = datetime.now(timezone.utc)
    epoch_diff = 116444736000000000
    filetime = int(now.timestamp() * 10_000_000) + epoch_diff
    av_pairs += struct.pack("<HHQ", 0x0007, 8, filetime)

    # EOL
    av_pairs += struct.pack("<HH", 0x0000, 0)

    target_name = config["netbios_domain"].encode("utf-16-le")

    # Header is 56 bytes (with version)
    target_offset = 56
    ti_offset = target_offset + len(target_name)

    msg = NTLMSSP_SIGNATURE
    msg += struct.pack("<I", 2)  # Type 2
    msg += struct.pack("<HHI", len(target_name), len(target_name), target_offset)
    msg += struct.pack("<I", flags)
    msg += b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"  # Server challenge
    msg += b"\x00" * 8  # Reserved
    msg += struct.pack("<HHI", len(av_pairs), len(av_pairs), ti_offset)

    # Version
    msg += struct.pack("<BBH", config["os_major"], config["os_minor"], config["os_build"])
    msg += b"\x00\x00\x00"
    msg += struct.pack("<B", 15)  # NTLM revision

    msg += target_name
    msg += av_pairs

    return msg


def wrap_spnego(ntlm_bytes: bytes) -> bytes:
    """Wrap NTLM in a minimal SPNEGO NegTokenResp (simplified but functional)."""
    # Build from inside out:
    # OCTET STRING containing NTLM message
    response_token = _asn1_tlv(0x04, ntlm_bytes)
    # Context [2] (responseToken)
    ctx2 = _asn1_tlv(0xa2, response_token)
    # SEQUENCE containing the context
    seq = _asn1_tlv(0x30, ctx2)
    # Context [1] (NegTokenResp)
    return _asn1_tlv(0xa1, seq)


def _asn1_tlv(tag: int, value: bytes) -> bytes:
    """Build a TLV (tag-length-value) ASN.1 element."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + value


class NTLMHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_OPTIONS(self):
        self._handle_request()

    def _handle_request(self):
        path = self.path.split("?")[0]

        # Serve HTML pages (for crawler)
        if path in PAGES:
            auth_header = self.headers.get("Authorization", "")
            if path in NTLM_ENDPOINTS:
                self._handle_ntlm(auth_header, path)
            else:
                self._serve_page(path)
            return

        # NTLM endpoints
        if path in NTLM_ENDPOINTS:
            auth_header = self.headers.get("Authorization", "")
            self._handle_ntlm(auth_header, path)
            return

        # Negotiate (SPNEGO) endpoints
        if path in NEGOTIATE_ENDPOINTS:
            auth_header = self.headers.get("Authorization", "")
            self._handle_negotiate(auth_header, path)
            return

        # Basic auth endpoints
        if path in BASIC_ENDPOINTS:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Test Realm"')
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Authentication required")
            return

        # 404
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Not Found")

    def _serve_page(self, path):
        html = PAGES[path]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())

    def _handle_ntlm(self, auth_header: str, path: str):
        if auth_header.upper().startswith("NTLM "):
            token = auth_header[5:].strip()
            try:
                raw = base64.b64decode(token)
                if raw[:8] == NTLMSSP_SIGNATURE:
                    msg_type = struct.unpack_from("<I", raw, 8)[0]
                    if msg_type == 1:
                        # Type 1 received -> send Type 2 challenge
                        challenge = build_challenge_message(DOMAIN_CONFIG)
                        challenge_b64 = base64.b64encode(challenge).decode()
                        self.send_response(401)
                        self.send_header("WWW-Authenticate", f"NTLM {challenge_b64}")
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(b"NTLM challenge issued")
                        return
            except Exception:
                pass

        # No auth or unrecognized -> request NTLM
        self.send_response(401)
        self.send_header("WWW-Authenticate", "NTLM")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"NTLM authentication required")

    def _handle_negotiate(self, auth_header: str, path: str):
        if auth_header.upper().startswith("NTLM ") or auth_header.upper().startswith("NEGOTIATE "):
            token = auth_header.split(None, 1)[1].strip()
            try:
                raw = base64.b64decode(token)
                # Check for NTLMSSP signature (might be inside SPNEGO)
                idx = raw.find(NTLMSSP_SIGNATURE)
                if idx >= 0:
                    ntlm_data = raw[idx:]
                    msg_type = struct.unpack_from("<I", ntlm_data, 8)[0]
                    if msg_type == 1:
                        challenge = build_challenge_message(DOMAIN_CONFIG)
                        spnego = wrap_spnego(challenge)
                        challenge_b64 = base64.b64encode(spnego).decode()
                        self.send_response(401)
                        self.send_header("WWW-Authenticate", f"Negotiate {challenge_b64}")
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(b"Negotiate challenge issued")
                        return
            except Exception:
                pass

        # No auth -> advertise Negotiate only (not bare NTLM)
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Negotiate")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Negotiate authentication required")


def run_server(port: int = 8888) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), NTLMHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    print(f"Mock NTLM server running on http://127.0.0.1:{port}")
    print(f"NTLM endpoints: {sorted(NTLM_ENDPOINTS)}")
    print(f"Negotiate endpoints: {sorted(NEGOTIATE_ENDPOINTS)}")
    print(f"Basic-only endpoints: {sorted(BASIC_ENDPOINTS)}")
    print(f"Crawlable pages: {sorted(PAGES.keys())}")
    print()
    print(f"Domain: {DOMAIN_CONFIG['netbios_domain']}\\{DOMAIN_CONFIG['netbios_computer']}")
    print(f"FQDN:   {DOMAIN_CONFIG['dns_computer']}")
    print()
    print("Press Ctrl+C to stop")
    server = HTTPServer(("127.0.0.1", port), NTLMHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()
