"""Attack categories and payload dataclass."""

from dataclasses import dataclass, field
from enum import Enum


class AttackCategory(Enum):
    """Categories of prompt injection attacks."""

    DIRECT_OVERRIDE = "direct_override"
    CONTEXT_MANIPULATION = "context_manipulation"
    PERSONA_HIJACK = "persona_hijack"
    DELIMITER_ESCAPE = "delimiter_escape"
    PAYLOAD_SMUGGLING = "payload_smuggling"
    ENCODING = "encoding"
    PLINY = "pliny"
    INDIRECT = "indirect"
    PROPAGATION = "propagation"


class AttackObjective(Enum):
    """What the injection is trying to achieve."""

    EXECUTE = "execute"      # LLM follows the injection's instruction directly
    PROPAGATE = "propagate"  # LLM embeds injection in response for downstream agents


class InjectionPosition(Enum):
    """Where the injection is placed relative to the legitimate message."""

    PREPEND = "prepend"
    APPEND = "append"
    EMBED = "embed"


@dataclass(frozen=True)
class AttackPayload:
    """A single prompt injection attack payload."""

    id: str
    category: AttackCategory
    name: str
    payload: str
    source: str
    targets: str
    position: InjectionPosition = InjectionPosition.APPEND
    objective: AttackObjective = AttackObjective.EXECUTE
    propagation_marker: str = ""  # string that should NOT appear in response content
