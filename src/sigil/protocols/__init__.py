"""Sigil protocol implementations."""

from sigil.protocols.canary import CanaryProtocol
from sigil.protocols.nonce_echo import NonceEchoProtocol
from sigil.protocols.schema_strict import SchemaStrictProtocol
from sigil.protocols.hmac_challenge import HMACChallengeProtocol
from sigil.protocols.combined import CombinedProtocol
from sigil.protocols.none import NoneProtocol

ALL_PROTOCOLS = [
    NoneProtocol,
    CanaryProtocol,
    NonceEchoProtocol,
    SchemaStrictProtocol,
    HMACChallengeProtocol,
    CombinedProtocol,
]

__all__ = [
    "NoneProtocol",
    "CanaryProtocol",
    "NonceEchoProtocol",
    "SchemaStrictProtocol",
    "HMACChallengeProtocol",
    "CombinedProtocol",
    "ALL_PROTOCOLS",
]
