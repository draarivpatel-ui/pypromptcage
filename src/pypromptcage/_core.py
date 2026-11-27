"""Dependency-free deterministic prompt and output security inspection.

The scanner uses bounded input sizes, bounded recursion, bounded finding
counts, and simple linear scans. It does not evaluate model behavior and it is
not a substitute for least privilege, tool allowlists, or output authorization.
"""

from __future__ import annotations

import base64
import math
import re
import unicodedata
from dataclasses import asdict, dataclass, field, replace
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qsl, urlsplit

VERSION = "1.0.0"

CODE = MappingProxyType({
    "INVALID_INPUT": "ERR_PYPROMPTCAGE_INVALID_INPUT",
    "INVALID_OPTIONS": "ERR_PYPROMPTCAGE_INVALID_OPTIONS",
    "INPUT_TOO_LARGE": "ERR_PYPROMPTCAGE_INPUT_TOO_LARGE",
    "BLOCKED": "ERR_PYPROMPTCAGE_BLOCKED",
})

DEFAULT_LIMITS = MappingProxyType({
    "max_input_length": 100000,
    "max_decoded_size": 65536,
    "max_encoded_depth": 3,
    "max_encoded_candidates": 32,
    "max_findings": 250,
})

_HARD_LIMITS = MappingProxyType({
    "max_input_length": 1000000,
    "max_decoded_size": 262144,
    "max_encoded_depth": 5,
    "max_encoded_candidates": 128,
    "max_findings": 1000,
    "max_canary_tokens": 64,
    "max_canary_token_length": 1024,
    "max_additional_phrases": 128,
    "max_additional_phrase_length": 256,
    "max_trusted_image_hosts": 128,
})

CWE_PROMPT_INJECTION = "CWE-1427"
CWE_ENCODING = "CWE-116"
CWE_EXPOSURE = "CWE-200"
OWASP_PROMPT_INJECTION = "LLM01:2025"
OWASP_SENSITIVE_DISCLOSURE = "LLM02:2025"


@dataclass(frozen=True)
class RuleMetadata:
    layer: str
    severity: str
    cwe: str
    owasp: str


def _rule(layer: str, severity: str, cwe: str, owasp: str) -> RuleMetadata:
    return RuleMetadata(layer=layer, severity=severity, cwe=cwe, owasp=owasp)


RULES = MappingProxyType({
    "GP-CORE-LIMIT-001": _rule("core", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-TAG-001": _rule("unicode", "critical", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-BIDI-001": _rule("unicode", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-ZW-001": _rule("unicode", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-VS-001": _rule("unicode", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-CTRL-001": _rule("unicode", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-CONFUSE-001": _rule("unicode", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-UNI-MIXED-001": _rule("unicode", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-ROLE-001": _rule("injection", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-TOKEN-001": _rule("injection", "critical", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-XML-001": _rule("injection", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-OVERRIDE-001": _rule("injection", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-PROMPT-001": _rule("injection", "critical", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-PERSONA-001": _rule("injection", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-INDIRECT-001": _rule("injection", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-DELIM-001": _rule("injection", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-TOOL-001": _rule("injection", "critical", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-STRUCT-001": _rule("injection", "critical", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-INJ-CUSTOM-001": _rule("injection", "medium", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-ENC-B64-001": _rule("encoding", "medium", CWE_ENCODING, OWASP_PROMPT_INJECTION),
    "GP-ENC-HEX-001": _rule("encoding", "medium", CWE_ENCODING, OWASP_PROMPT_INJECTION),
    "GP-ENC-URL-001": _rule("encoding", "medium", CWE_ENCODING, OWASP_PROMPT_INJECTION),
    "GP-ENC-ROT13-001": _rule("encoding", "high", CWE_ENCODING, OWASP_PROMPT_INJECTION),
    "GP-ENC-NEST-001": _rule("encoding", "high", CWE_PROMPT_INJECTION, OWASP_PROMPT_INJECTION),
    "GP-ENC-LIMIT-001": _rule("encoding", "medium", CWE_ENCODING, OWASP_PROMPT_INJECTION),
    "GP-EGR-CANARY-001": _rule("egress", "critical", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-MARKDOWN-IMG-001": _rule("egress", "high", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-DATAURL-001": _rule("egress", "high", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-CREDENTIAL-001": _rule("egress", "critical", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-PRIVATEKEY-001": _rule("egress", "critical", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-PII-001": _rule("egress", "high", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-URL-EXFIL-001": _rule("egress", "high", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
    "GP-EGR-HIGHENTROPY-001": _rule("egress", "medium", CWE_EXPOSURE, OWASP_SENSITIVE_DISCLOSURE),
})

_SEVERITY_WEIGHT = {"low": 5, "medium": 12, "high": 25, "critical": 40}
_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class PromptCageError(ValueError):
    """Structured error raised by pypromptcage."""

    def __init__(
        self,
        code: str,
        reason: str,
        input_value: Any = None,
        findings: Optional[Sequence["Finding"]] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(code + ": " + reason)
        self.code = code
        self.reason = reason
        if input_value is not None:
            self.input = input_value
        if findings is not None:
            self.findings = tuple(findings)
        if cause is not None:
            self.cause = cause

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {"name": type(self).__name__, "code": self.code, "reason": self.reason}
        if hasattr(self, "input"):
            output["input"] = self.input
        if hasattr(self, "findings"):
            output["findings"] = [finding.to_dict() for finding in self.findings]
        return output


@dataclass(frozen=True)
class PromptCageOptions:
    max_input_length: int = DEFAULT_LIMITS["max_input_length"]
    max_decoded_size: int = DEFAULT_LIMITS["max_decoded_size"]
    max_encoded_depth: int = DEFAULT_LIMITS["max_encoded_depth"]
    max_encoded_candidates: int = DEFAULT_LIMITS["max_encoded_candidates"]
    max_findings: int = DEFAULT_LIMITS["max_findings"]
    redaction_token: str = "[redacted]"
    warn_threshold: int = 12
    block_threshold: int = 70
    decode_encoded: bool = True
    scan_encoded: bool = True
    normalize_unicode: bool = True
    canary_tokens: Tuple[str, ...] = ()
    additional_phrases: Tuple[str, ...] = ()
    trusted_image_hosts: Tuple[str, ...] = ()
    include_canonical: bool = True


_OPTION_KEYS = set(PromptCageOptions.__dataclass_fields__.keys())


@dataclass(frozen=True)
class Finding:
    id: str
    layer: str
    severity: str
    cwe: str
    owasp: str
    description: str
    evidence: str
    start: int = -1
    end: int = -1
    path: Tuple[str, ...] = ()
    nested_rule: Optional[str] = None
    count: Optional[int] = None
    decoded_length: Optional[int] = None
    scripts: Tuple[str, ...] = ()
    decoded: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["path"] = list(self.path)
        result["scripts"] = list(self.scripts)
        return result


@dataclass(frozen=True)
class HiddenSegment:
    text: str
    start: int
    end: int
    length: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UnicodeScanResult:
    canonical: str
    findings: Tuple[Finding, ...]
    hidden_segments: Tuple[HiddenSegment, ...]
    stats: Mapping[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical": self.canonical,
            "findings": [finding.to_dict() for finding in self.findings],
            "hidden_segments": [segment.to_dict() for segment in self.hidden_segments],
            "stats": dict(self.stats),
        }


@dataclass(frozen=True)
class EncodedPayload:
    encoding: str
    path: Tuple[str, ...]
    depth: int
    start: int
    end: int
    length: int
    preview: str

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["path"] = list(self.path)
        return result


@dataclass(frozen=True)
class EncodedScanResult:
    findings: Tuple[Finding, ...]
    payloads: Tuple[EncodedPayload, ...]
    stats: Mapping[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "payloads": [payload.to_dict() for payload in self.payloads],
            "stats": dict(self.stats),
        }


@dataclass(frozen=True)
class InspectionReport:
    kind: str
    action: str
    risk_score: int
    risk_level: str
    input_length: int
    canonical_length: int
    findings: Tuple[Finding, ...]
    finding_count: int
    truncated: bool
    redacted: str
    canonical: Optional[str]
    stats: Mapping[str, int]
    unicode: Mapping[str, int] = field(default_factory=dict)
    hidden_segment_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "action": self.action,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "input_length": self.input_length,
            "canonical_length": self.canonical_length,
            "findings": [finding.to_dict() for finding in self.findings],
            "finding_count": self.finding_count,
            "truncated": self.truncated,
            "redacted": self.redacted,
            "canonical": self.canonical,
            "stats": dict(self.stats),
            "unicode": dict(self.unicode),
            "hidden_segment_count": self.hidden_segment_count,
        }


def _options_error(reason: str, value: Any = None) -> None:
    raise PromptCageError(CODE["INVALID_OPTIONS"], reason, value)


def _bounded_integer(value: Any, key: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        _options_error(key + " must be an integer between " + str(minimum) + " and " + str(maximum), value)
    return value


def _string_tuple_option(value: Any, key: str, maximum_items: int, maximum_length: int) -> Tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        _options_error(key + " must be a list or tuple of strings", value)
    if len(value) > maximum_items:
        _options_error(key + " has too many entries", len(value))
    output: List[str] = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            _options_error(key + " entries must be strings", item)
        if len(item) == 0 or len(item) > maximum_length:
            _options_error(key + " entries must have length 1 to " + str(maximum_length), len(item))
        if item not in seen:
            seen.add(item)
            output.append(item)
    return tuple(output)


def normalize_options(options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> PromptCageOptions:
    """Validate and normalize caller options into an immutable options object."""

    if options is None:
        values: Dict[str, Any] = {}
    elif isinstance(options, PromptCageOptions):
        values = asdict(options)
    elif isinstance(options, Mapping):
        values = dict(options)
    else:
        _options_error("options must be a PromptCageOptions object or a mapping", options)

    for key in values:
        if key not in _OPTION_KEYS:
            _options_error("unknown option: " + key, key)

    merged = asdict(PromptCageOptions())
    merged.update(values)

    merged["max_input_length"] = _bounded_integer(merged["max_input_length"], "max_input_length", 128, _HARD_LIMITS["max_input_length"])
    merged["max_decoded_size"] = _bounded_integer(merged["max_decoded_size"], "max_decoded_size", 256, _HARD_LIMITS["max_decoded_size"])
    merged["max_encoded_depth"] = _bounded_integer(merged["max_encoded_depth"], "max_encoded_depth", 0, _HARD_LIMITS["max_encoded_depth"])
    merged["max_encoded_candidates"] = _bounded_integer(merged["max_encoded_candidates"], "max_encoded_candidates", 1, _HARD_LIMITS["max_encoded_candidates"])
    merged["max_findings"] = _bounded_integer(merged["max_findings"], "max_findings", 16, _HARD_LIMITS["max_findings"])

    token = merged["redaction_token"]
    if not isinstance(token, str) or len(token) == 0 or len(token) > 80 or "\n" in token or "\r" in token:
        _options_error("redaction_token must be a single-line string of length 1 to 80", token)
    merged["warn_threshold"] = _bounded_integer(merged["warn_threshold"], "warn_threshold", 0, 100)
    merged["block_threshold"] = _bounded_integer(merged["block_threshold"], "block_threshold", 1, 100)
    if merged["warn_threshold"] > merged["block_threshold"]:
        _options_error("warn_threshold must not exceed block_threshold", {
            "warn_threshold": merged["warn_threshold"],
            "block_threshold": merged["block_threshold"],
        })
    for key in ("decode_encoded", "scan_encoded", "normalize_unicode", "include_canonical"):
        if not isinstance(merged[key], bool):
            _options_error(key + " must be a boolean", merged[key])

    merged["canary_tokens"] = _string_tuple_option(
        merged["canary_tokens"], "canary_tokens", _HARD_LIMITS["max_canary_tokens"], _HARD_LIMITS["max_canary_token_length"]
    )
    merged["additional_phrases"] = _string_tuple_option(
        merged["additional_phrases"], "additional_phrases", _HARD_LIMITS["max_additional_phrases"], _HARD_LIMITS["max_additional_phrase_length"]
    )
    hosts = _string_tuple_option(
        merged["trusted_image_hosts"], "trusted_image_hosts", _HARD_LIMITS["max_trusted_image_hosts"], 253
    )
    merged["trusted_image_hosts"] = tuple(dict.fromkeys(host.lower() for host in hosts))
    return PromptCageOptions(**merged)


def _assert_bounded_string(value: Any, options: PromptCageOptions, noun: str) -> str:
    if not isinstance(value, str):
        raise PromptCageError(CODE["INVALID_INPUT"], noun + " must be a string", type(value).__name__)
    if len(value) > options.max_input_length:
        raise PromptCageError(
            CODE["INPUT_TOO_LARGE"],
            noun + " length " + str(len(value)) + " exceeds max_input_length " + str(options.max_input_length),
            len(value),
        )
    return value


def _hex_code_point(cp: int) -> str:
    return "U+" + format(cp, "04X")


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_printable_tag_char(cp: int) -> bool:
    return 0xE0020 <= cp <= 0xE007E


def _is_bidi_control(cp: int) -> bool:
    return 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069


def _is_zero_width(cp: int) -> bool:
    return cp in {0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF}


def _is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _is_restricted_control(cp: int) -> bool:
    return 0x0000 <= cp <= 0x0008 or cp in {0x000B, 0x000C} or 0x000E <= cp <= 0x001F or 0x007F <= cp <= 0x009F


def _is_invisible_or_restricted(cp: int) -> bool:
    return _is_tag_char(cp) or _is_bidi_control(cp) or _is_zero_width(cp) or _is_variation_selector(cp) or _is_restricted_control(cp)


def _clean_evidence(value: Any, maximum: int = 160) -> str:
    output = ""
    for ch in str(value):
        cp = ord(ch)
        if cp in (9, 10, 13):
            output += " "
        elif _is_invisible_or_restricted(cp):
            output += "<" + _hex_code_point(cp) + ">"
        else:
            output += ch
        if len(output) >= maximum:
            break
    output = re.sub(r"[ \t]+", " ", output).strip()
    if len(output) > maximum:
        output = output[: maximum - 1] + "~"
    return output


def _make_finding(
    rule_id: str,
    description: str,
    evidence: Any,
    start: int = -1,
    end: int = -1,
    *,
    severity: Optional[str] = None,
    path: Sequence[str] = (),
    nested_rule: Optional[str] = None,
    count: Optional[int] = None,
    decoded_length: Optional[int] = None,
    scripts: Sequence[str] = (),
    decoded: Optional[str] = None,
) -> Finding:
    meta = RULES[rule_id]
    return Finding(
        id=rule_id,
        layer=meta.layer,
        severity=severity or meta.severity,
        cwe=meta.cwe,
        owasp=meta.owasp,
        description=description,
        evidence=_clean_evidence(evidence),
        start=start,
        end=end,
        path=tuple(path),
        nested_rule=nested_rule,
        count=count,
        decoded_length=decoded_length,
        scripts=tuple(scripts),
        decoded=decoded,
    )


def _push_capped(findings: List[Finding], finding: Finding, cap: int = 8) -> None:
    count = sum(1 for existing in findings if existing.id == finding.id)
    if count < cap:
        findings.append(finding)


def _find_all_occurrences(text: str, needle: str) -> List[int]:
    positions: List[int] = []
    if not needle:
        return positions
    index = text.find(needle)
    while index != -1 and len(positions) < 32:
        positions.append(index)
        index = text.find(needle, index + len(needle))
    return positions


_CONFUSABLE_MAP = {
    "\u0430": "a", "\u0410": "A",
    "\u0435": "e", "\u0415": "E",
    "\u043e": "o", "\u041e": "O",
    "\u0440": "p", "\u0420": "P",
    "\u0441": "c", "\u0421": "C",
    "\u0445": "x", "\u0425": "X",
    "\u0443": "y", "\u0423": "Y",
    "\u0456": "i", "\u0406": "I",
    "\u0458": "j", "\u0408": "J",
    "\u04bb": "h", "\u04ba": "H",
    "\u0455": "s", "\u0405": "S",
    "\u03b1": "a", "\u0391": "A",
    "\u03b5": "e", "\u0395": "E",
    "\u03bf": "o", "\u039f": "O",
    "\u03c1": "p", "\u03a1": "P",
    "\u03ba": "k", "\u039a": "K",
    "\u03c4": "t", "\u03a4": "T",
    "\u03bd": "v", "\u039d": "N",
    "\u03bc": "u", "\u039c": "M",
    "\u03b7": "n", "\u0397": "H",
    "\u03b9": "i", "\u0399": "I",
    "\u03c7": "x", "\u03a7": "X",
    "\u0442": "t", "\u0422": "T",
    "\u043c": "m", "\u041c": "M",
    "\u043d": "h", "\u041d": "H",
    "\u0432": "b", "\u0412": "B",
}


def _script_of_code_point(cp: int) -> Optional[str]:
    if 0x0041 <= cp <= 0x005A or 0x0061 <= cp <= 0x007A or 0x00C0 <= cp <= 0x024F or 0x1E00 <= cp <= 0x1EFF:
        return "Latin"
    if 0x0370 <= cp <= 0x03FF or 0x1F00 <= cp <= 0x1FFF:
        return "Greek"
    if 0x0400 <= cp <= 0x052F or 0x2DE0 <= cp <= 0x2DFF or 0xA640 <= cp <= 0xA69F:
        return "Cyrillic"
    if 0x0590 <= cp <= 0x05FF:
        return "Hebrew"
    if 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F or 0x08A0 <= cp <= 0x08FF:
        return "Arabic"
    if 0x0900 <= cp <= 0x097F:
        return "Devanagari"
    if 0x4E00 <= cp <= 0x9FFF:
        return "Han"
    if 0x3040 <= cp <= 0x309F:
        return "Hiragana"
    if 0x30A0 <= cp <= 0x30FF:
        return "Katakana"
    if 0xAC00 <= cp <= 0xD7AF:
        return "Hangul"
    if 0x0E00 <= cp <= 0x0E7F:
        return "Thai"
    if 0x0530 <= cp <= 0x058F:
        return "Armenian"
    if 0x10A0 <= cp <= 0x10FF:
        return "Georgian"
    return None


def _is_token_character(ch: str) -> bool:
    cp = ord(ch)
    return _script_of_code_point(cp) is not None or 0x0030 <= cp <= 0x0039 or ch in {"_", "-", "\u2010"}


def _mixed_script_tokens(text: str) -> List[Dict[str, Any]]:
    suspicious: List[Dict[str, Any]] = []
    token_start = -1
    token = ""
    scripts = set()

    def flush(end: int) -> None:
        nonlocal token_start, token, scripts
        if token_start != -1:
            if len(scripts) > 1 and "Latin" in scripts and len(token) >= 2:
                suspicious.append({"token": token, "start": token_start, "end": end, "scripts": sorted(scripts)})
        token_start = -1
        token = ""
        scripts = set()

    for index, ch in enumerate(text):
        if _is_token_character(ch):
            if token_start == -1:
                token_start = index
            token += ch
            script = _script_of_code_point(ord(ch))
            if script:
                scripts.add(script)
        else:
            flush(index)
    flush(len(text))
    return suspicious[:8]


def _decode_tag_runs(text: str) -> Tuple[List[HiddenSegment], int, int]:
    segments: List[HiddenSegment] = []
    current = ""
    start = -1
    count = 0
    first = -1

    def flush(end: int) -> None:
        nonlocal current, start
        if current:
            segments.append(HiddenSegment(text=current, start=start, end=end, length=len(current)))
        current = ""
        start = -1

    for index, ch in enumerate(text):
        cp = ord(ch)
        if _is_tag_char(cp):
            count += 1
            if first == -1:
                first = index
            if _is_printable_tag_char(cp):
                if start == -1:
                    start = index
                current += chr(cp - 0xE0000)
            else:
                flush(index)
        else:
            flush(index)
    flush(len(text))
    return segments, count, first


def scan_unicode(input_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> UnicodeScanResult:
    opts = normalize_options(options)
    input_text = _assert_bounded_string(input_text, opts, "input")

    counts = {"tags": 0, "bidi": 0, "zero_width": 0, "variation_selectors": 0, "controls": 0, "confusables": 0}
    first_positions = {"tags": -1, "bidi": -1, "zero_width": -1, "variation_selectors": -1, "controls": -1, "confusables": -1}
    confusable_examples: List[str] = []
    segments, tag_count, tag_first = _decode_tag_runs(input_text)
    counts["tags"] = tag_count
    first_positions["tags"] = tag_first

    for index, ch in enumerate(input_text):
        cp = ord(ch)
        if _is_bidi_control(cp):
            counts["bidi"] += 1
            if first_positions["bidi"] == -1:
                first_positions["bidi"] = index
        if _is_zero_width(cp):
            counts["zero_width"] += 1
            if first_positions["zero_width"] == -1:
                first_positions["zero_width"] = index
        if _is_variation_selector(cp):
            counts["variation_selectors"] += 1
            if first_positions["variation_selectors"] == -1:
                first_positions["variation_selectors"] = index
        if _is_restricted_control(cp):
            counts["controls"] += 1
            if first_positions["controls"] == -1:
                first_positions["controls"] = index

    normalized = unicodedata.normalize("NFKC", input_text) if opts.normalize_unicode else input_text
    canonical_chars: List[str] = []
    for index, ch in enumerate(normalized):
        cp = ord(ch)
        if _is_tag_char(cp) or _is_bidi_control(cp) or _is_zero_width(cp) or _is_variation_selector(cp) or _is_restricted_control(cp):
            continue
        replacement = _CONFUSABLE_MAP.get(ch)
        if replacement is not None:
            counts["confusables"] += 1
            if first_positions["confusables"] == -1:
                first_positions["confusables"] = index
            if len(confusable_examples) < 8:
                confusable_examples.append(_hex_code_point(cp) + "->" + replacement)
            canonical_chars.append(replacement)
        else:
            canonical_chars.append(ch)
    canonical = "".join(canonical_chars)

    findings: List[Finding] = []
    if counts["tags"]:
        decoded_preview = " ".join(segment.text for segment in segments).strip()
        findings.append(_make_finding(
            "GP-UNI-TAG-001",
            "Unicode Tag characters encode a covert instruction channel",
            (str(counts["tags"]) + " tag characters decode to: " + decoded_preview) if decoded_preview else str(counts["tags"]) + " non-printing tag characters",
            first_positions["tags"],
            first_positions["tags"] + 1,
            count=counts["tags"],
            decoded=decoded_preview or None,
        ))
    if counts["bidi"]:
        findings.append(_make_finding("GP-UNI-BIDI-001", "Bidirectional override or isolate control can reorder visible text", str(counts["bidi"]) + " bidi control characters", first_positions["bidi"], first_positions["bidi"] + 1, count=counts["bidi"]))
    if counts["zero_width"]:
        findings.append(_make_finding("GP-UNI-ZW-001", "Zero-width characters can hide steganographic payload separators", str(counts["zero_width"]) + " zero-width characters", first_positions["zero_width"], first_positions["zero_width"] + 1, count=counts["zero_width"]))
    if counts["variation_selectors"]:
        findings.append(_make_finding("GP-UNI-VS-001", "Variation selectors can carry a hidden byte channel", str(counts["variation_selectors"]) + " variation selectors", first_positions["variation_selectors"], first_positions["variation_selectors"] + 1, count=counts["variation_selectors"]))
    if counts["controls"]:
        findings.append(_make_finding("GP-UNI-CTRL-001", "Restricted control characters can alter prompt framing or terminal display", str(counts["controls"]) + " restricted control characters", first_positions["controls"], first_positions["controls"] + 1, count=counts["controls"]))
    if counts["confusables"]:
        findings.append(_make_finding("GP-UNI-CONFUSE-001", "Mixed-script confusable characters were canonicalized to their Latin lookalikes", ", ".join(confusable_examples), first_positions["confusables"], first_positions["confusables"] + 1, count=counts["confusables"]))
    for item in _mixed_script_tokens(canonical):
        _push_capped(findings, _make_finding(
            "GP-UNI-MIXED-001",
            "A single token mixes scripts, a common homoglyph spoofing signal",
            item["token"] + " uses " + " and ".join(item["scripts"]),
            item["start"],
            item["end"],
            scripts=item["scripts"],
        ), 4)

    stats = dict(counts)
    stats["input_length"] = len(input_text)
    stats["canonical_length"] = len(canonical)
    return UnicodeScanResult(canonical=canonical, findings=tuple(findings), hidden_segments=tuple(segments), stats=MappingProxyType(stats))


_EXACT_PATTERNS = (
    ("<|im_start|>", "GP-INJ-TOKEN-001", "Chat template start control token"),
    ("<|im_end|>", "GP-INJ-TOKEN-001", "Chat template end control token"),
    ("<|endoftext|>", "GP-INJ-TOKEN-001", "Model end-of-text control token"),
    ("<|system|>", "GP-INJ-TOKEN-001", "Model system-role control token"),
    ("<|assistant|>", "GP-INJ-TOKEN-001", "Model assistant-role control token"),
    ("<|user|>", "GP-INJ-TOKEN-001", "Model user-role control token"),
    ("<|endofprompt|>", "GP-INJ-TOKEN-001", "Prompt boundary control token"),
    ("[inst]", "GP-INJ-TOKEN-001", "Instruction template delimiter"),
    ("[/inst]", "GP-INJ-TOKEN-001", "Instruction template closing delimiter"),
    ("<<sys>>", "GP-INJ-TOKEN-001", "System template delimiter"),
    ("<</sys>>", "GP-INJ-TOKEN-001", "System template closing delimiter"),
    ("[system]", "GP-INJ-TOKEN-001", "Serialized system-role delimiter"),
    ("[assistant]", "GP-INJ-TOKEN-001", "Serialized assistant-role delimiter"),
    ("<system>", "GP-INJ-XML-001", "XML-style system prompt tag"),
    ("</system>", "GP-INJ-XML-001", "XML-style system prompt closing tag"),
    ("<assistant>", "GP-INJ-XML-001", "XML-style assistant transcript tag"),
    ("</assistant>", "GP-INJ-XML-001", "XML-style assistant transcript closing tag"),
    ("<user>", "GP-INJ-XML-001", "XML-style user transcript tag"),
    ("</user>", "GP-INJ-XML-001", "XML-style user transcript closing tag"),
    ("<instruction>", "GP-INJ-XML-001", "XML-style instruction tag"),
    ("</instruction>", "GP-INJ-XML-001", "XML-style instruction closing tag"),
    ("<system_prompt>", "GP-INJ-XML-001", "XML-style system prompt tag"),
    ("</system_prompt>", "GP-INJ-XML-001", "XML-style system prompt closing tag"),
    ("<tool_call>", "GP-INJ-TOOL-001", "Forged XML tool-call tag"),
    ("</tool_call>", "GP-INJ-TOOL-001", "Forged XML tool-call closing tag"),
    ("<function_call>", "GP-INJ-TOOL-001", "Forged XML function-call tag"),
    ("</function_call>", "GP-INJ-TOOL-001", "Forged XML function-call closing tag"),
    ("<tool_response>", "GP-INJ-TOOL-001", "Forged XML tool-response tag"),
    ("</tool_response>", "GP-INJ-TOOL-001", "Forged XML tool-response closing tag"),
    ('"tool_calls"', "GP-INJ-TOOL-001", "Serialized tool_calls key"),
    ("'tool_calls'", "GP-INJ-TOOL-001", "Serialized tool_calls key"),
    ('"function_call"', "GP-INJ-TOOL-001", "Serialized function_call key"),
    ("tool_call:", "GP-INJ-TOOL-001", "Serialized tool-call field"),
    ("function_call:", "GP-INJ-TOOL-001", "Serialized function-call field"),
    ("call_tool(", "GP-INJ-TOOL-001", "Inline tool invocation syntax"),
    ("use_tool(", "GP-INJ-TOOL-001", "Inline tool invocation syntax"),
    ("run_tool(", "GP-INJ-TOOL-001", "Inline tool invocation syntax"),
    ("execute_tool(", "GP-INJ-TOOL-001", "Inline tool invocation syntax"),
    ("end of system prompt", "GP-INJ-DELIM-001", "Transcript boundary escape phrase"),
    ("end of user input", "GP-INJ-DELIM-001", "Transcript boundary escape phrase"),
    ("end user input", "GP-INJ-DELIM-001", "Transcript boundary escape phrase"),
    ("system message resumes", "GP-INJ-DELIM-001", "Transcript boundary escape phrase"),
    ("return to system instructions", "GP-INJ-DELIM-001", "Transcript boundary escape phrase"),
    ("close user input", "GP-INJ-DELIM-001", "Transcript boundary escape phrase"),
    ("begin system message", "GP-INJ-DELIM-001", "Transcript boundary spoofing phrase"),
    ("new system message", "GP-INJ-DELIM-001", "Transcript boundary spoofing phrase"),
    ("you are now", "GP-INJ-PERSONA-001", "Persona reset phrase"),
    ("pretend you are", "GP-INJ-PERSONA-001", "Persona spoofing phrase"),
    ("pretend to be", "GP-INJ-PERSONA-001", "Persona spoofing phrase"),
    ("act as if you are", "GP-INJ-PERSONA-001", "Persona spoofing phrase"),
    ("act as an unrestricted", "GP-INJ-PERSONA-001", "Unrestricted-persona jailbreak phrase"),
    ("developer mode", "GP-INJ-PERSONA-001", "Developer-mode jailbreak phrase"),
    ("dan mode", "GP-INJ-PERSONA-001", "Named jailbreak mode"),
    ("do anything now", "GP-INJ-PERSONA-001", "Named jailbreak instruction"),
    ("without restrictions", "GP-INJ-PERSONA-001", "Restriction removal phrase"),
    ("ignore safety", "GP-INJ-PERSONA-001", "Safety bypass instruction"),
    ("bypass safety", "GP-INJ-PERSONA-001", "Safety bypass instruction"),
    ("when the assistant reads this", "GP-INJ-INDIRECT-001", "Indirect injection addressed to a downstream assistant"),
    ("when an ai reads this", "GP-INJ-INDIRECT-001", "Indirect injection addressed to a downstream model"),
    ("the assistant must", "GP-INJ-INDIRECT-001", "Instruction addressed to the assistant rather than the user"),
    ("the ai must", "GP-INJ-INDIRECT-001", "Instruction addressed to the model rather than the user"),
    ("assistant should follow", "GP-INJ-INDIRECT-001", "Indirect assistant instruction"),
    ("follow these instructions instead", "GP-INJ-INDIRECT-001", "Instruction replacement phrase"),
    ("instructions for the assistant", "GP-INJ-INDIRECT-001", "Indirect assistant instruction block"),
    ("instructions to the assistant", "GP-INJ-INDIRECT-001", "Indirect assistant instruction block"),
    ("dear assistant", "GP-INJ-INDIRECT-001", "Indirect assistant instruction block"),
    ("attention assistant", "GP-INJ-INDIRECT-001", "Indirect assistant instruction block"),
    ("if you are an ai", "GP-INJ-INDIRECT-001", "Model-directed conditional instruction"),
    ("if you are a language model", "GP-INJ-INDIRECT-001", "Model-directed conditional instruction"),
    ("as an ai assistant you must", "GP-INJ-INDIRECT-001", "Model-directed imperative"),
    ("downstream model", "GP-INJ-INDIRECT-001", "Reference to a downstream model recipient"),
)

_OVERRIDE_START_WORDS = ("ignore", "disregard", "forget", "override", "bypass")
_INSTRUCTION_TARGET_WORDS = ("instructions", "directives", "rules", "system prompt", "safety guidelines", "constraints")
_PROMPT_EXFIL_VERBS = ("reveal", "show", "print", "repeat", "disclose", "leak", "output", "expose", "tell", "display", "dump")
_PROMPT_EXFIL_TARGETS = ("system prompt", "hidden instructions", "initial instructions", "developer instructions", "original instructions", "system message", "your instructions", "the instructions")


def _scan_windowed_instruction_patterns(lower: str, findings: List[Finding]) -> None:
    for start_word in _OVERRIDE_START_WORDS:
        for start in _find_all_occurrences(lower, start_word):
            window = lower[start : min(len(lower), start + 140)]
            target = next((item for item in _INSTRUCTION_TARGET_WORDS if item in window), None)
            if target:
                end = min(len(lower), start + window.index(target) + len(target))
                _push_capped(findings, _make_finding(
                    "GP-INJ-OVERRIDE-001",
                    "Instruction-override phrase attempts to replace prior directives",
                    lower[start:end],
                    start,
                    end,
                ))

    for verb in _PROMPT_EXFIL_VERBS:
        for start in _find_all_occurrences(lower, verb):
            window = lower[start : min(len(lower), start + 130)]
            target = next((item for item in _PROMPT_EXFIL_TARGETS if item in window), None)
            if target:
                end = min(len(lower), start + window.index(target) + len(target))
                _push_capped(findings, _make_finding(
                    "GP-INJ-PROMPT-001",
                    "Request attempts to expose hidden or system instructions",
                    lower[start:end],
                    start,
                    end,
                ))


_ROLE_LINE_RE = re.compile(r"^[\t ]{0,12}(system|assistant|user|developer|tool|human|ai)[\t ]*:[\t ]*\S", re.IGNORECASE)
_HEADING_RE = re.compile(r"^[\t ]{0,6}#{1,6}[\t ]+(system|instructions|system prompt|developer message)\b", re.IGNORECASE)
_FENCE_RE = re.compile(r"```[\t ]*(system|instructions|prompt|json)\b", re.IGNORECASE)
_DOUBLE_ROLE_RE = re.compile(r'"role"[\t ]*:[\t ]*"(system|assistant|user|tool)"', re.IGNORECASE)
_SINGLE_ROLE_RE = re.compile(r"'role'[\t ]*:[\t ]*'(system|assistant|user|tool)'", re.IGNORECASE)
_INVOKE_RE = re.compile(r"<\/?(?:tool_call|function_call|tool_response|invoke|function_results?)\b[^>]{0,200}>", re.IGNORECASE)
_JSON_TOOL_RE = re.compile(r'"(?:tool_calls|function_call)"[\t ]*:', re.IGNORECASE)


def _scan_regex_findings(input_text: str, regex: re.Pattern[str], rule_id: str, description: str, findings: List[Finding]) -> None:
    for count, match in enumerate(regex.finditer(input_text)):
        if count >= 8:
            break
        _push_capped(findings, _make_finding(rule_id, description, match.group(0), match.start(), match.end()))


def scan_injection(input_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> Tuple[Finding, ...]:
    opts = normalize_options(options)
    input_text = _assert_bounded_string(input_text, opts, "input")
    lower = input_text.lower()
    findings: List[Finding] = []

    for needle, rule_id, description in _EXACT_PATTERNS:
        for start in _find_all_occurrences(lower, needle):
            _push_capped(findings, _make_finding(rule_id, description, input_text[start : start + len(needle)], start, start + len(needle)))

    offset = 0
    for raw_line in input_text.splitlines(True):
        line = raw_line.rstrip("\r\n")
        if _ROLE_LINE_RE.search(line):
            end = min(len(input_text), offset + len(line))
            _push_capped(findings, _make_finding("GP-INJ-ROLE-001", "Line spoofs a chat-role boundary label", line, offset, end))
        if _HEADING_RE.search(line):
            end = min(len(input_text), offset + len(line))
            _push_capped(findings, _make_finding("GP-INJ-DELIM-001", "Markdown heading imitates a system or instruction boundary", line, offset, end))
        offset += len(raw_line)
    if input_text and not input_text.splitlines(True) and input_text.strip():
        if _ROLE_LINE_RE.search(input_text):
            _push_capped(findings, _make_finding("GP-INJ-ROLE-001", "Line spoofs a chat-role boundary label", input_text[:120], 0, min(len(input_text), 120)))

    _scan_regex_findings(input_text, _FENCE_RE, "GP-INJ-DELIM-001", "Markdown code fence imitates a privileged prompt boundary", findings)
    _scan_regex_findings(input_text, _DOUBLE_ROLE_RE, "GP-INJ-STRUCT-001", "Serialized message object assigns a privileged role", findings)
    _scan_regex_findings(input_text, _SINGLE_ROLE_RE, "GP-INJ-STRUCT-001", "Serialized message object assigns a privileged role", findings)
    _scan_regex_findings(input_text, _INVOKE_RE, "GP-INJ-TOOL-001", "XML-like tool invocation or response forgery", findings)
    _scan_regex_findings(input_text, _JSON_TOOL_RE, "GP-INJ-TOOL-001", "Serialized tool invocation key forgery", findings)
    _scan_windowed_instruction_patterns(lower, findings)

    for phrase in opts.additional_phrases:
        needle = phrase.lower()
        for start in _find_all_occurrences(lower, needle):
            _push_capped(findings, _make_finding("GP-INJ-CUSTOM-001", "Input matches a caller-supplied blocked phrase", input_text[start : start + len(phrase)], start, start + len(phrase)))

    findings.sort(key=lambda finding: (finding.start, finding.id))
    return tuple(findings)


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    bad = 0
    for ch in text:
        cp = ord(ch)
        if (cp < 32 and cp not in (9, 10, 13)) or cp == 127 or _is_tag_char(cp):
            bad += 1
    return bad / len(text) <= 0.15


def _utf8_decode(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None


def _decode_base64_candidate(token: str, max_bytes: int) -> Optional[str]:
    if len(token) < 20 or len(token) > 2048 or len(token) % 4 == 1:
        return None
    padding = 0
    alphabet_seen = False
    upper = lower = digit = symbol = False
    for index, ch in enumerate(token):
        if "A" <= ch <= "Z":
            upper = True
        elif "a" <= ch <= "z":
            lower = True
        elif "0" <= ch <= "9":
            digit = True
        elif ch in "+/":
            symbol = True
        elif ch == "=":
            padding += 1
            if padding > 2 or index < len(token) - 2:
                return None
        else:
            return None
        if ch != "=":
            alphabet_seen = True
    if not alphabet_seen or not (digit or symbol or padding or (upper and lower)):
        return None
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        decoded = base64.b64decode(padded.encode("ascii"), validate=True)
    except Exception:
        return None
    if not decoded or len(decoded) > max_bytes:
        return None
    canonical = base64.b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != token.rstrip("="):
        return None
    text = _utf8_decode(decoded)
    if text is None or not _is_mostly_printable(text):
        return None
    return text


def _decode_hex_candidate(token: str, max_bytes: int) -> Optional[str]:
    if len(token) < 20 or len(token) > 2048 or len(token) % 2:
        return None
    if any(ch not in "0123456789abcdefABCDEF" for ch in token):
        return None
    try:
        decoded = bytes.fromhex(token)
    except ValueError:
        return None
    if not decoded or len(decoded) > max_bytes:
        return None
    text = _utf8_decode(decoded)
    if text is None or not _is_mostly_printable(text):
        return None
    return text


def _is_hex_digit(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _percent_decode_candidate(token: str, max_bytes: int) -> Optional[str]:
    if len(token) < 6 or len(token) > 2048:
        return None
    encoded_count = 0
    data = bytearray()
    index = 0
    while index < len(token):
        ch = token[index]
        if ch == "%":
            if index + 2 >= len(token) or not _is_hex_digit(token[index + 1]) or not _is_hex_digit(token[index + 2]):
                return None
            data.append(int(token[index + 1 : index + 3], 16))
            encoded_count += 1
            index += 3
        elif ch == "+":
            data.append(32)
            index += 1
        else:
            if ord(ch) > 127:
                return None
            data.append(ord(ch))
            index += 1
        if len(data) > max_bytes:
            return None
    if encoded_count < 2:
        return None
    text = _utf8_decode(bytes(data))
    if text is None or not _is_mostly_printable(text):
        return None
    return text


def _is_token_delimiter(ch: Optional[str]) -> bool:
    return ch is None or ch.isspace() or ch in {'"', "'", "`", "<", ">", "(", ")", "[", "]", "{", "}", ","}


def _count_percent_hex_sequences(token: str) -> int:
    count = 0
    for index in range(0, max(0, len(token) - 2)):
        if token[index] == "%" and _is_hex_digit(token[index + 1]) and _is_hex_digit(token[index + 2]):
            count += 1
    return count


def _encoded_value_character(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch in {"+", "/", "%", "-", ".", "_", "~", "="})


def _push_encoded_candidate(tokens: List[Dict[str, Any]], seen: set, candidate_type: str, token: str, start: int, end: int) -> None:
    if not token or len(token) > 2048:
        return
    key = (start, end, candidate_type)
    if key in seen:
        return
    seen.add(key)
    if candidate_type == "url" or len(token) >= 20:
        tokens.append({"type": candidate_type, "token": token, "start": start, "end": end})


def _add_embedded_encoded_candidates(tokens: List[Dict[str, Any]], seen: set, outer_token: str, outer_start: int) -> None:
    for index, ch in enumerate(outer_token):
        if ch != "=":
            continue
        end = index + 1
        while end < len(outer_token) and _encoded_value_character(outer_token[end]):
            end += 1
        value = outer_token[index + 1 : end]
        if len(value) < 6:
            continue
        absolute_start = outer_start + index + 1
        absolute_end = outer_start + end
        if _count_percent_hex_sequences(value) >= 2:
            _push_encoded_candidate(tokens, seen, "url", value, absolute_start, absolute_end)
        else:
            _push_encoded_candidate(tokens, seen, "auto", value, absolute_start, absolute_end)


def _extract_encoded_tokens(text: str) -> List[Dict[str, Any]]:
    tokens: List[Dict[str, Any]] = []
    seen = set()
    start = -1
    token = ""

    def flush(end: int) -> None:
        nonlocal start, token
        if start != -1 and len(token) <= 2048:
            if _count_percent_hex_sequences(token) >= 2:
                _push_encoded_candidate(tokens, seen, "url", token, start, end)
            else:
                _push_encoded_candidate(tokens, seen, "auto", token, start, end)
            _add_embedded_encoded_candidates(tokens, seen, token, start)
        start = -1
        token = ""

    for index, ch in enumerate(text):
        if ord(ch) <= 127 and not _is_token_delimiter(ch) and ch != "=":
            if start == -1:
                start = index
            token += ch
        elif ord(ch) <= 127 and ch == "=" and start != -1:
            token += ch
        else:
            flush(index)
    flush(len(text))
    return tokens[: _HARD_LIMITS["max_encoded_candidates"]]

def _rot13(text: str) -> str:
    output: List[str] = []
    for ch in text:
        cp = ord(ch)
        if 65 <= cp <= 90:
            output.append(chr(((cp - 65 + 13) % 26) + 65))
        elif 97 <= cp <= 122:
            output.append(chr(((cp - 97 + 13) % 26) + 97))
        else:
            output.append(ch)
    return "".join(output)


def _encoding_rule_for(encoding_type: str) -> str:
    if encoding_type == "base64":
        return "GP-ENC-B64-001"
    if encoding_type == "hex":
        return "GP-ENC-HEX-001"
    return "GP-ENC-URL-001"


def _add_encoded_limit(findings: List[Finding], reason: str, start: int, end: int) -> None:
    if not any(finding.id == "GP-ENC-LIMIT-001" for finding in findings):
        findings.append(_make_finding("GP-ENC-LIMIT-001", "Encoded-payload inspection stopped at a deterministic safety limit", reason, start, end))


def _clone_nested_finding(finding: Finding, path: Sequence[str], encoding: str) -> Finding:
    return replace(
        finding,
        description=finding.description + " inside decoded " + encoding + " payload",
        start=-1,
        end=-1,
        path=tuple(path),
        nested_rule=finding.id,
    )


def _collect_encoded_layer(
    text: str,
    path: Tuple[str, ...],
    depth: int,
    state: Dict[str, Any],
    opts: PromptCageOptions,
    findings: List[Finding],
    payloads: List[EncodedPayload],
) -> None:
    if depth >= opts.max_encoded_depth:
        return
    candidates = _extract_encoded_tokens(text)

    for candidate in candidates:
        if state["candidates"] >= opts.max_encoded_candidates:
            _add_encoded_limit(findings, "candidate count limit reached", candidate["start"], candidate["end"])
            return
        state["candidates"] += 1

        decoded: Optional[str] = None
        encoding_type = ""
        if candidate["type"] == "url":
            decoded = _percent_decode_candidate(candidate["token"], opts.max_decoded_size)
            encoding_type = "url"
        else:
            decoded = _decode_base64_candidate(candidate["token"], opts.max_decoded_size)
            encoding_type = "base64"
            if decoded is None:
                decoded = _decode_hex_candidate(candidate["token"], opts.max_decoded_size)
                encoding_type = "hex"
        if decoded is None or not decoded or decoded == candidate["token"]:
            continue

        if state["bytes"] + len(decoded.encode("utf-8")) > opts.max_decoded_size:
            _add_encoded_limit(findings, "decoded byte budget exceeded", candidate["start"], candidate["end"])
            return
        key = encoding_type + ":" + str(len(decoded)) + ":" + decoded
        if key in state["seen"]:
            continue
        state["seen"].add(key)
        state["bytes"] += len(decoded.encode("utf-8"))

        next_path = path + (encoding_type,)
        payloads.append(EncodedPayload(
            encoding=encoding_type,
            path=next_path,
            depth=depth + 1,
            start=candidate["start"],
            end=candidate["end"],
            length=len(decoded),
            preview=_clean_evidence(decoded, 100),
        ))
        findings.append(_make_finding(
            _encoding_rule_for(encoding_type),
            "Inspectable " + encoding_type + " encoded payload was decoded under configured limits",
            "decoded length " + str(len(decoded)) + ": " + decoded,
            candidate["start"],
            candidate["end"],
            path=next_path,
            decoded_length=len(decoded),
        ))

        nested = scan_injection(decoded, opts)
        if nested:
            findings.append(_make_finding(
                "GP-ENC-NEST-001",
                "Decoded payload contains prompt-injection content",
                nested[0].id + ": " + nested[0].evidence,
                candidate["start"],
                candidate["end"],
                path=next_path,
                nested_rule=nested[0].id,
            ))
            for nested_finding in nested[:6]:
                findings.append(_clone_nested_finding(nested_finding, next_path, encoding_type))
        _collect_encoded_layer(decoded, next_path, depth + 1, state, opts, findings, payloads)

    if len(text) >= 8 and any(ch.isalpha() and ord(ch) < 128 for ch in text):
        rotated = _rot13(text)
        nested = scan_injection(rotated, opts)
        if nested:
            first = nested[0]
            findings.append(_make_finding(
                "GP-ENC-ROT13-001",
                "ROT13-transformed text contains prompt-injection content",
                first.id + ": " + first.evidence,
                max(0, first.start),
                max(0, first.end),
                path=path + ("rot13",),
                nested_rule=first.id,
            ))
            for nested_finding in nested[:4]:
                findings.append(_clone_nested_finding(nested_finding, path + ("rot13",), "rot13"))


def scan_encoded(input_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> EncodedScanResult:
    opts = normalize_options(options)
    input_text = _assert_bounded_string(input_text, opts, "input")
    findings: List[Finding] = []
    payloads: List[EncodedPayload] = []
    if not opts.decode_encoded or opts.max_encoded_depth == 0:
        return EncodedScanResult(findings=tuple(), payloads=tuple(), stats=MappingProxyType({"candidates": 0, "decoded_bytes": 0, "depth": 0}))
    state: Dict[str, Any] = {"bytes": 0, "candidates": 0, "seen": set()}
    _collect_encoded_layer(input_text, tuple(), 0, state, opts, findings, payloads)
    return EncodedScanResult(
        findings=tuple(findings),
        payloads=tuple(payloads),
        stats=MappingProxyType({"candidates": state["candidates"], "decoded_bytes": state["bytes"], "depth": opts.max_encoded_depth}),
    )


def _merge_overlapping_spans(spans: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(spans, key=lambda item: (item[0], -item[1])):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    return merged


def _redact_canonical(canonical: str, findings: Sequence[Finding], redaction_token: str) -> str:
    spans: List[Tuple[int, int]] = []
    for finding in findings:
        if finding.start >= 0 and finding.end > finding.start and _SEVERITY_ORDER[finding.severity] >= _SEVERITY_ORDER["medium"]:
            spans.append((min(finding.start, len(canonical)), min(finding.end, len(canonical))))
    if not spans:
        return canonical
    output = ""
    cursor = 0
    for start, end in _merge_overlapping_spans(spans):
        output += canonical[cursor:start]
        output += redaction_token
        cursor = end
    output += canonical[cursor:]
    return output


def _dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    output: List[Finding] = []
    seen = set()
    for finding in findings:
        key = (finding.id, finding.start, finding.end, finding.evidence, finding.path)
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output


def _calculate_risk(findings: Sequence[Finding]) -> int:
    first_seen = set()
    score = 0
    for finding in findings:
        if finding.id not in first_seen:
            first_seen.add(finding.id)
            score += _SEVERITY_WEIGHT.get(finding.severity, 0)
        else:
            score += 2
    return min(100, score)


def _risk_level(score: int) -> str:
    if score == 0:
        return "none"
    if score < 20:
        return "low"
    if score < 50:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def _action_for(findings: Sequence[Finding], score: int, opts: PromptCageOptions) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "block"
    if score >= opts.block_threshold:
        return "block"
    if score >= opts.warn_threshold:
        return "warn"
    return "allow"


def _finalize_report(
    kind: str,
    input_text: str,
    canonical: str,
    findings: Sequence[Finding],
    opts: PromptCageOptions,
    unicode_stats: Mapping[str, int],
    hidden_segment_count: int,
) -> InspectionReport:
    deduped = _dedupe_findings(findings)
    truncated = len(deduped) > opts.max_findings
    capped = deduped[: opts.max_findings] if truncated else deduped
    risk_score = _calculate_risk(capped)
    stats = {
        "critical": sum(1 for finding in capped if finding.severity == "critical"),
        "high": sum(1 for finding in capped if finding.severity == "high"),
        "medium": sum(1 for finding in capped if finding.severity == "medium"),
        "low": sum(1 for finding in capped if finding.severity == "low"),
    }
    return InspectionReport(
        kind=kind,
        action=_action_for(capped, risk_score, opts),
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        input_length=len(input_text),
        canonical_length=len(canonical),
        findings=tuple(capped),
        finding_count=len(capped),
        truncated=truncated,
        redacted=_redact_canonical(canonical, capped, opts.redaction_token),
        canonical=canonical if opts.include_canonical else None,
        stats=MappingProxyType(stats),
        unicode=unicode_stats,
        hidden_segment_count=hidden_segment_count,
    )


def inspect_prompt(input_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
    """Inspect untrusted input text before it is placed in an LLM prompt."""

    opts = normalize_options(options)
    input_text = _assert_bounded_string(input_text, opts, "input")
    unicode_result = scan_unicode(input_text, opts)
    findings: List[Finding] = list(unicode_result.findings)

    for segment in unicode_result.hidden_segments:
        nested = scan_injection(segment.text, opts)
        for nested_finding in nested[:8]:
            findings.append(_clone_nested_finding(nested_finding, ("unicode-tags",), "unicode tag channel"))

    findings.extend(scan_injection(unicode_result.canonical, opts))
    if opts.scan_encoded:
        findings.extend(scan_encoded(unicode_result.canonical, opts).findings)

    return _finalize_report("input", input_text, unicode_result.canonical, findings, opts, unicode_result.stats, len(unicode_result.hidden_segments))


def _host_is_trusted(hostname: str, trusted_hosts: Sequence[str]) -> bool:
    host = hostname.lower()
    return any(host == trusted or host.endswith("." + trusted) for trusted in trusted_hosts)


def _parse_url_safely(value: str):
    try:
        return urlsplit(value)
    except ValueError:
        return None


def _summarize_url(parsed: Any) -> str:
    keys: List[str] = []
    try:
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if key not in keys and len(keys) < 8:
                keys.append(key)
    except Exception:
        return parsed.hostname or "unknown-host"
    host = parsed.hostname or "unknown-host"
    return host + (" query keys: " + ",".join(keys) if keys else " no query keys")


def _suspicious_url_exfiltration(parsed: Any) -> Dict[str, bool]:
    suspicious_key = False
    long_value = False
    encoded_shape = False
    suspicious_names = {"data", "token", "secret", "key", "password", "prompt", "system", "history", "messages", "context", "payload", "session"}
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        pairs = []
    for key, value in pairs:
        lower_key = key.lower()
        if lower_key in suspicious_names or "token" in lower_key or "secret" in lower_key or "key" in lower_key:
            suspicious_key = True
        if len(value) >= 24:
            long_value = True
        if re.fullmatch(r"[A-Za-z0-9_+/=-]{20,512}", value):
            encoded_shape = True
    return {"suspicious_key": suspicious_key, "long_value": long_value, "encoded_shape": encoded_shape, "exfiltrating": suspicious_key and (long_value or encoded_shape)}


_MD_IMAGE_RE = re.compile(r"!\[[^\]\r\n]{0,200}\]\((https?://[^\s)]{1,1000})\)", re.IGNORECASE)
_DATA_URL_RE = re.compile(r"\bdata:([a-z0-9!#$&^_.+-]{1,80}/[a-z0-9!#$&^_.+-]{1,80})?(;base64)?,[^\s)\"'<>]{8,1000}", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN(?: [A-Z0-9]{1,30})? PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bauthorization[\t ]*:[\t ]*bearer[\t ]+([A-Za-z0-9._~+/=-]{8,256})", re.IGNORECASE)
_SECRET_ASSIGNMENT_RE = re.compile(r"\b(api[_-]?key|token|access[_-]?token|auth[_-]?token|secret|password|client[_-]?secret|private[_-]?token)\b[\t ]*[:=][\t ]*[\"']?([^\"'\s,;]{8,256})", re.IGNORECASE)
_JSON_SECRET_RE = re.compile(r"[\"'](api[_-]?key|token|access[_-]?token|auth[_-]?token|secret|password|client[_-]?secret|private[_-]?token)[\"'][\t ]*:[\t ]*[\"']([^\"']{8,256})[\"']", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,256}\.[A-Za-z0-9_-]{10,256}\.[A-Za-z0-9_-]{8,256}\b")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,24}\b", re.IGNORECASE)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARDISH_RE = re.compile(r"(?:\d[ -]?){13,19}")
_URL_RE = re.compile(r"\bhttps?://[^\s)\"'<>]{4,1000}", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_+./=-]{24,256}")


def _shannon_entropy(text: str) -> float:
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / len(text)
        entropy -= probability * math.log2(probability)
    return entropy


def _character_class_count(text: str) -> int:
    classes = 0
    if any("a" <= ch <= "z" for ch in text):
        classes += 1
    if any("A" <= ch <= "Z" for ch in text):
        classes += 1
    if any("0" <= ch <= "9" for ch in text):
        classes += 1
    if any(not ch.isalnum() for ch in text):
        classes += 1
    return classes


def _luhn_valid(digits: str) -> bool:
    total = 0
    double_digit = False
    for ch in reversed(digits):
        value = ord(ch) - 48
        if double_digit:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        double_digit = not double_digit
    return total % 10 == 0


def _overlaps_existing(findings: Sequence[Finding], start: int, end: int, ids: set) -> bool:
    for finding in findings:
        if finding.id in ids and finding.start >= 0 and start < finding.end and end > finding.start:
            return True
    return False


def scan_egress(output_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> Tuple[Finding, ...]:
    opts = normalize_options(options)
    output_text = _assert_bounded_string(output_text, opts, "output")
    findings: List[Finding] = []

    for canary in opts.canary_tokens:
        for start in _find_all_occurrences(output_text, canary):
            _push_capped(findings, _make_finding("GP-EGR-CANARY-001", "Output contains a caller-registered canary token", "canary token of length " + str(len(canary)), start, start + len(canary)))

    for count, match in enumerate(_MD_IMAGE_RE.finditer(output_text)):
        if count >= 12:
            break
        parsed = _parse_url_safely(match.group(1))
        if parsed is None or not parsed.hostname:
            continue
        if _host_is_trusted(parsed.hostname, opts.trusted_image_hosts):
            continue
        severity = "high" if parsed.query else "medium"
        _push_capped(findings, _make_finding("GP-EGR-MARKDOWN-IMG-001", "Markdown image URL can be used as a passive data-exfiltration channel", _summarize_url(parsed), match.start(), match.end(), severity=severity))

    for count, match in enumerate(_DATA_URL_RE.finditer(output_text)):
        if count >= 12:
            break
        severity = "high" if len(match.group(0)) > 200 or ";base64" in match.group(0).lower() else "medium"
        _push_capped(findings, _make_finding("GP-EGR-DATAURL-001", "Suspicious data URL can embed hidden or browser-rendered content", "data URL length " + str(len(match.group(0))), match.start(), match.end(), severity=severity))

    for count, match in enumerate(_PRIVATE_KEY_RE.finditer(output_text)):
        if count >= 12:
            break
        _push_capped(findings, _make_finding("GP-EGR-PRIVATEKEY-001", "Output contains a private-key block boundary", match.group(0), match.start(), match.end()))

    for count, match in enumerate(_BEARER_RE.finditer(output_text)):
        if count >= 12:
            break
        _push_capped(findings, _make_finding("GP-EGR-CREDENTIAL-001", "Output contains an authorization bearer credential", "bearer credential length " + str(len(match.group(1))), match.start(), match.end()))

    for count, match in enumerate(_SECRET_ASSIGNMENT_RE.finditer(output_text)):
        if count >= 12:
            break
        _push_capped(findings, _make_finding("GP-EGR-CREDENTIAL-001", "Output contains a secret-like credential assignment", match.group(1) + " value length " + str(len(match.group(2))), match.start(), match.end()))

    for count, match in enumerate(_JSON_SECRET_RE.finditer(output_text)):
        if count >= 12:
            break
        _push_capped(findings, _make_finding("GP-EGR-CREDENTIAL-001", "Output contains a serialized secret-like credential field", match.group(1) + " value length " + str(len(match.group(2))), match.start(), match.end()))

    for count, match in enumerate(_JWT_RE.finditer(output_text)):
        if count >= 12:
            break
        _push_capped(findings, _make_finding("GP-EGR-CREDENTIAL-001", "Output contains a three-part token shape", "token length " + str(len(match.group(0))), match.start(), match.end()))

    for count, match in enumerate(_EMAIL_RE.finditer(output_text)):
        if count >= 12:
            break
        local, _, domain = match.group(0).partition("@")
        masked = local[:2] + "***@" + domain
        _push_capped(findings, _make_finding("GP-EGR-PII-001", "Output contains an email address", masked, match.start(), match.end()))

    for count, match in enumerate(_SSN_RE.finditer(output_text)):
        if count >= 12:
            break
        _push_capped(findings, _make_finding("GP-EGR-PII-001", "Output contains a national-identifier-shaped number", "identifier pattern with length " + str(len(match.group(0))), match.start(), match.end()))

    for count, match in enumerate(_CARDISH_RE.finditer(output_text)):
        if count >= 8:
            break
        digits = re.sub(r"[^0-9]", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            _push_capped(findings, _make_finding("GP-EGR-PII-001", "Output contains a payment-card-shaped number that passes checksum validation", "payment card length " + str(len(digits)), match.start(), match.end()))

    for count, match in enumerate(_URL_RE.finditer(output_text)):
        if count >= 12:
            break
        parsed = _parse_url_safely(match.group(0))
        if parsed is None or not parsed.hostname:
            continue
        assessment = _suspicious_url_exfiltration(parsed)
        if not assessment["exfiltrating"]:
            continue
        _push_capped(findings, _make_finding("GP-EGR-URL-EXFIL-001", "URL query has a sensitive key and an encoded or long value", _summarize_url(parsed), match.start(), match.end()))

    for count, match in enumerate(_TOKEN_RE.finditer(output_text)):
        if count >= 12:
            break
        token = match.group(0)
        start, end = match.start(), match.end()
        if _overlaps_existing(findings, start, end, {"GP-EGR-CREDENTIAL-001", "GP-EGR-PRIVATEKEY-001", "GP-EGR-URL-EXFIL-001", "GP-EGR-MARKDOWN-IMG-001"}):
            continue
        entropy = _shannon_entropy(token)
        classes = _character_class_count(token)
        strong_shape = len(token) >= 32 and entropy >= 4.0 and classes >= 3
        hex_shape = len(token) >= 40 and re.fullmatch(r"[0-9a-fA-F]+", token) is not None and entropy >= 3.4
        if strong_shape or hex_shape:
            _push_capped(findings, _make_finding("GP-EGR-HIGHENTROPY-001", "Output contains a high-entropy token-shaped value", "length " + str(len(token)) + ", entropy " + format(entropy, ".2f"), start, end))

    findings.sort(key=lambda finding: (finding.start, finding.id))
    return tuple(findings)


def inspect_output(output_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
    """Inspect model or agent output before rendering, publishing, or executing it."""

    opts = normalize_options(options)
    output_text = _assert_bounded_string(output_text, opts, "output")
    unicode_result = scan_unicode(output_text, opts)
    findings: List[Finding] = list(unicode_result.findings)
    findings.extend(scan_egress(unicode_result.canonical, opts))
    return _finalize_report("output", output_text, unicode_result.canonical, findings, opts, unicode_result.stats, len(unicode_result.hidden_segments))


def sanitize_prompt(input_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> str:
    return inspect_prompt(input_text, options).redacted


def sanitize_output(output_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> str:
    return inspect_output(output_text, options).redacted


def assert_safe_prompt(input_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
    report = inspect_prompt(input_text, options)
    if report.action == "block":
        raise PromptCageError(CODE["BLOCKED"], "input blocked by pypromptcage policy", findings=report.findings)
    return report


def assert_safe_output(output_text: str, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
    report = inspect_output(output_text, options)
    if report.action == "block":
        raise PromptCageError(CODE["BLOCKED"], "output blocked by pypromptcage policy", findings=report.findings)
    return report


def _merge_options(base: PromptCageOptions, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]]) -> PromptCageOptions:
    if overrides is None:
        return base
    base_values = asdict(base)
    if isinstance(overrides, PromptCageOptions):
        override_values = asdict(overrides)
    elif isinstance(overrides, Mapping):
        override_values = dict(overrides)
    else:
        _options_error("overrides must be a PromptCageOptions object or a mapping", overrides)
    base_values.update(override_values)
    return normalize_options(base_values)


class PromptFirewall:
    """Reusable firewall object with prevalidated base options."""

    def __init__(self, options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> None:
        self._options = normalize_options(options)

    @property
    def options(self) -> PromptCageOptions:
        return self._options

    def inspect_prompt(self, input_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
        return inspect_prompt(input_text, _merge_options(self._options, overrides))

    def inspect_output(self, output_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
        return inspect_output(output_text, _merge_options(self._options, overrides))

    def sanitize_prompt(self, input_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> str:
        return self.inspect_prompt(input_text, overrides).redacted

    def sanitize_output(self, output_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> str:
        return self.inspect_output(output_text, overrides).redacted

    def assert_safe_prompt(self, input_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
        report = self.inspect_prompt(input_text, overrides)
        if report.action == "block":
            raise PromptCageError(CODE["BLOCKED"], "input blocked by pypromptcage policy", findings=report.findings)
        return report

    def assert_safe_output(self, output_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> InspectionReport:
        report = self.inspect_output(output_text, overrides)
        if report.action == "block":
            raise PromptCageError(CODE["BLOCKED"], "output blocked by pypromptcage policy", findings=report.findings)
        return report

    def scan_unicode(self, input_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> UnicodeScanResult:
        return scan_unicode(input_text, _merge_options(self._options, overrides))

    def scan_injection(self, input_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> Tuple[Finding, ...]:
        return scan_injection(input_text, _merge_options(self._options, overrides))

    def scan_encoded(self, input_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> EncodedScanResult:
        return scan_encoded(input_text, _merge_options(self._options, overrides))

    def scan_egress(self, output_text: str, overrides: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> Tuple[Finding, ...]:
        return scan_egress(output_text, _merge_options(self._options, overrides))


def create_prompt_firewall(options: Optional[Union[PromptCageOptions, Mapping[str, Any]]] = None) -> PromptFirewall:
    return PromptFirewall(options)
