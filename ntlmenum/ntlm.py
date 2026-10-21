"""
NTLM message construction and parsing.
Handles Type 1 (Negotiate), Type 2 (Challenge) parsing,
and SPNEGO/Negotiate token unwrapping.
"""

import base64
import struct
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field


NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

# Negotiate flags
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_OEM = 0x00000002
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_NEGOTIATE_56 = 0x80000000

NEGOTIATE_FLAGS_MAP = {
    NTLMSSP_NEGOTIATE_UNICODE: "NEGOTIATE_UNICODE",
    NTLMSSP_NEGOTIATE_OEM: "NEGOTIATE_OEM",
    NTLMSSP_REQUEST_TARGET: "REQUEST_TARGET",
    NTLMSSP_NEGOTIATE_SIGN: "NEGOTIATE_SIGN",
    NTLMSSP_NEGOTIATE_SEAL: "NEGOTIATE_SEAL",
    NTLMSSP_NEGOTIATE_DATAGRAM: "NEGOTIATE_DATAGRAM",
    NTLMSSP_NEGOTIATE_LM_KEY: "NEGOTIATE_LM_KEY",
    NTLMSSP_NEGOTIATE_NTLM: "NEGOTIATE_NTLM",
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: "OEM_DOMAIN_SUPPLIED",
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED: "OEM_WORKSTATION_SUPPLIED",
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN: "NEGOTIATE_ALWAYS_SIGN",
    NTLMSSP_TARGET_TYPE_DOMAIN: "TARGET_TYPE_DOMAIN",
    NTLMSSP_TARGET_TYPE_SERVER: "TARGET_TYPE_SERVER",
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: "NEGOTIATE_EXTENDED_SESSIONSECURITY",
    NTLMSSP_NEGOTIATE_IDENTIFY: "NEGOTIATE_IDENTIFY",
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY: "REQUEST_NON_NT_SESSION_KEY",
    NTLMSSP_NEGOTIATE_TARGET_INFO: "NEGOTIATE_TARGET_INFO",
    NTLMSSP_NEGOTIATE_VERSION: "NEGOTIATE_VERSION",
    NTLMSSP_NEGOTIATE_128: "NEGOTIATE_128",
    NTLMSSP_NEGOTIATE_KEY_EXCH: "NEGOTIATE_KEY_EXCH",
    NTLMSSP_NEGOTIATE_56: "NEGOTIATE_56",
}

# AV_PAIR types
AV_PAIR_TYPES = {
    0x0000: "MsvAvEOL",
    0x0001: "MsvAvNbComputerName",
    0x0002: "MsvAvNbDomainName",
    0x0003: "MsvAvDnsComputerName",
    0x0004: "MsvAvDnsDomainName",
    0x0005: "MsvAvDnsTreeName",
    0x0006: "MsvAvFlags",
    0x0007: "MsvAvTimestamp",
    0x0008: "MsvAvSingleHost",
    0x0009: "MsvAvTargetName",
    0x000A: "MsvAvChannelBindings",
}

# Windows version mapping (major.minor -> product name)
WINDOWS_VERSIONS = {
    (5, 1): "Windows XP",
    (5, 2): "Windows Server 2003",
    (6, 0): "Windows Vista / Server 2008",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (10, 0): "Windows 10/11 / Server 2016+",
}


@dataclass
class NTLMVersion:
    major: int = 0
    minor: int = 0
    build: int = 0
    revision: int = 0

    @property
    def product_name(self) -> str:
        return WINDOWS_VERSIONS.get((self.major, self.minor), "Unknown")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}"


@dataclass
class NTLMChallenge:
    """Parsed NTLM Type 2 (Challenge) message."""
    target_name: str = ""
    negotiate_flags: int = 0
    server_challenge: bytes = b""
    version: NTLMVersion | None = None
    av_pairs: dict[str, str | int | datetime] = field(default_factory=dict)
    raw_flags: list[str] = field(default_factory=list)
    timestamp: datetime | None = None

    @property
    def netbios_computer_name(self) -> str:
        return self.av_pairs.get("MsvAvNbComputerName", "")

    @property
    def netbios_domain_name(self) -> str:
        return self.av_pairs.get("MsvAvNbDomainName", "")

    @property
    def dns_computer_name(self) -> str:
        return self.av_pairs.get("MsvAvDnsComputerName", "")

    @property
    def dns_domain_name(self) -> str:
        return self.av_pairs.get("MsvAvDnsDomainName", "")

    @property
    def dns_tree_name(self) -> str:
        return self.av_pairs.get("MsvAvDnsTreeName", "")

    @property
    def target_name_from_av(self) -> str:
        return self.av_pairs.get("MsvAvTargetName", "")

    def flag_names(self) -> list[str]:
        names = []
        for flag_val, flag_name in NEGOTIATE_FLAGS_MAP.items():
            if self.negotiate_flags & flag_val:
                names.append(flag_name)
        return names

    def supports_ntlmv1(self) -> bool:
        return not bool(
            self.negotiate_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

    def to_dict(self) -> dict:
        result = {
            "target_name": self.target_name,
            "netbios_computer_name": self.netbios_computer_name,
            "netbios_domain_name": self.netbios_domain_name,
            "dns_computer_name": self.dns_computer_name,
            "dns_domain_name": self.dns_domain_name,
            "dns_tree_name": self.dns_tree_name,
            "negotiate_flags": self.flag_names(),
            "supports_ntlmv1": self.supports_ntlmv1(),
        }
        if self.version:
            result["os_version"] = str(self.version)
            result["os_build"] = self.version.build
            result["os_product"] = self.version.product_name
        if self.timestamp:
            result["timestamp"] = self.timestamp.isoformat()
        return result


def build_ntlm_negotiate() -> bytes:
    """Build an NTLM Type 1 (Negotiate) message."""
    flags = (
        NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_OEM
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
    )

    # Type 1 message structure
    msg = NTLMSSP_SIGNATURE
    msg += struct.pack("<I", 1)  # MessageType = Negotiate
    msg += struct.pack("<I", flags)
    # DomainNameFields (Len, MaxLen, Offset) - empty
    msg += struct.pack("<HHI", 0, 0, 0)
    # WorkstationFields (Len, MaxLen, Offset) - empty
    msg += struct.pack("<HHI", 0, 0, 0)
    # Version (8 bytes): 10.0.19041, NTLM revision 15
    msg += struct.pack("<BBH", 10, 0, 19041)
    msg += b"\x00\x00\x00"
    msg += struct.pack("<B", 15)

    return msg


def build_ntlm_negotiate_b64() -> str:
    """Return base64-encoded NTLM Type 1 message."""
    return base64.b64encode(build_ntlm_negotiate()).decode("ascii")


def _parse_av_pairs(data: bytes) -> dict[str, str | int | datetime]:
    """Parse AV_PAIR structures from target info block."""
    pairs = {}
    offset = 0
    while offset + 4 <= len(data):
        av_id, av_len = struct.unpack_from("<HH", data, offset)
        offset += 4
        if av_id == 0x0000:  # MsvAvEOL
            break
        if offset + av_len > len(data):
            break

        av_data = data[offset : offset + av_len]
        av_name = AV_PAIR_TYPES.get(av_id, f"Unknown_0x{av_id:04x}")

        if av_id in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0009):
            # Unicode string types
            try:
                pairs[av_name] = av_data.decode("utf-16-le")
            except UnicodeDecodeError:
                pairs[av_name] = av_data.hex()
        elif av_id == 0x0006:
            # MsvAvFlags (uint32)
            if av_len >= 4:
                pairs[av_name] = struct.unpack_from("<I", av_data)[0]
        elif av_id == 0x0007:
            # MsvAvTimestamp (FILETIME - 100ns intervals since 1601-01-01)
            if av_len >= 8:
                filetime = struct.unpack_from("<Q", av_data)[0]
                epoch_diff = 116444736000000000  # 100ns intervals between 1601 and 1970
                unix_us = (filetime - epoch_diff) // 10
                try:
                    pairs[av_name] = datetime.fromtimestamp(
                        unix_us / 1_000_000, tz=timezone.utc
                    )
                except (OSError, OverflowError, ValueError):
                    pairs[av_name] = f"raw:{filetime}"
        else:
            pairs[av_name] = av_data.hex()

        offset += av_len

    return pairs


def _parse_version(data: bytes, offset: int) -> NTLMVersion | None:
    """Parse 8-byte version structure at given offset."""
    if offset + 8 > len(data):
        return None
    major, minor, build = struct.unpack_from("<BBH", data, offset)
    revision = struct.unpack_from("<B", data, offset + 7)[0]
    if major == 0 and minor == 0 and build == 0:
        return None
    return NTLMVersion(major=major, minor=minor, build=build, revision=revision)


def parse_ntlm_challenge(raw: bytes) -> NTLMChallenge:
    """Parse an NTLM Type 2 (Challenge) message."""
    challenge = NTLMChallenge()

    if len(raw) < 32:
        raise ValueError(f"NTLM challenge too short: {len(raw)} bytes")
    if raw[:8] != NTLMSSP_SIGNATURE:
        raise ValueError("Invalid NTLMSSP signature")

    msg_type = struct.unpack_from("<I", raw, 8)[0]
    if msg_type != 2:
        raise ValueError(f"Not a Type 2 message: type={msg_type}")

    # Target Name fields
    tn_len, tn_max, tn_offset = struct.unpack_from("<HHI", raw, 12)
    if tn_offset + tn_len <= len(raw):
        try:
            challenge.target_name = raw[tn_offset : tn_offset + tn_len].decode(
                "utf-16-le"
            )
        except UnicodeDecodeError:
            challenge.target_name = raw[tn_offset : tn_offset + tn_len].hex()

    # Negotiate flags
    challenge.negotiate_flags = struct.unpack_from("<I", raw, 20)[0]

    # Server challenge (8 bytes at offset 24)
    challenge.server_challenge = raw[24:32]

    # Version (at offset 48 if NEGOTIATE_VERSION flag is set)
    if challenge.negotiate_flags & NTLMSSP_NEGOTIATE_VERSION and len(raw) >= 56:
        challenge.version = _parse_version(raw, 48)

    # Target Info (if NEGOTIATE_TARGET_INFO flag is set)
    if challenge.negotiate_flags & NTLMSSP_NEGOTIATE_TARGET_INFO and len(raw) >= 44:
        ti_len, ti_max, ti_offset = struct.unpack_from("<HHI", raw, 40)
        if ti_offset + ti_len <= len(raw):
            challenge.av_pairs = _parse_av_pairs(raw[ti_offset : ti_offset + ti_len])

    # Extract timestamp from AV pairs
    ts = challenge.av_pairs.get("MsvAvTimestamp")
    if isinstance(ts, datetime):
        challenge.timestamp = ts

    return challenge


def unwrap_spnego(token_b64: str) -> bytes | None:
    """
    Attempt to unwrap NTLM from a SPNEGO/Negotiate token.
    Returns raw NTLM bytes if found, None otherwise.
    """
    try:
        data = base64.b64decode(token_b64)
    except Exception:
        return None

    # Direct NTLM
    if data[:8] == NTLMSSP_SIGNATURE:
        return data

    # SPNEGO wraps NTLM in ASN.1. We do a pragmatic search for the NTLMSSP signature
    # rather than a full ASN.1 parser, since we only need the NTLM payload.
    idx = data.find(NTLMSSP_SIGNATURE)
    if idx >= 0:
        return data[idx:]

    return None


def extract_ntlm_challenge(header_value: str) -> NTLMChallenge | None:
    """
    Extract and parse NTLM challenge from an HTTP auth header value.
    Handles both bare 'NTLM <base64>' and 'Negotiate <base64>' tokens.
    """
    parts = header_value.strip().split(None, 1)
    if len(parts) != 2:
        return None

    scheme, token_b64 = parts
    scheme_lower = scheme.lower()

    if scheme_lower not in ("ntlm", "negotiate"):
        return None

    # Try direct base64 decode for bare NTLM
    if scheme_lower == "ntlm":
        try:
            raw = base64.b64decode(token_b64)
            if raw[:8] == NTLMSSP_SIGNATURE:
                return parse_ntlm_challenge(raw)
        except Exception:
            pass

    # Try SPNEGO unwrap (works for both Negotiate and NTLM schemes)
    raw = unwrap_spnego(token_b64)
    if raw is not None:
        try:
            return parse_ntlm_challenge(raw)
        except ValueError:
            pass

    return None
