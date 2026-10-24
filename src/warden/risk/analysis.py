"""Deterministic risk analysis of one proposed action.

Pure function of a ``RiskRequest``: no filesystem access, no network, no model call, so the
same request always gets the same findings wherever the analyst runs. Evidence strings name
only workspace-relative paths, sizes and counts, never file content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

from warden.risk.contract import MAX_EVIDENCE_CHARS, MAX_FINDINGS, RiskFinding, RiskRequest

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
LEVEL_FOR_RANK = {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
RECOMMENDATION = {"LOW": "ALLOW_CANDIDATE", "MEDIUM": "ESCALATE", "HIGH": "ESCALATE", "CRITICAL": "BLOCK_CANDIDATE"}

DESTRUCTIVE = {"DELETE", "RENAME", "WRITE"}
SENSITIVE_NAME = re.compile(
    r"(^\.env|\.env$|secret|credential|passw|token|private|\.pem$|\.key$|id_rsa|\.p12$|\.pfx$|wallet|seed)",
    re.IGNORECASE,
)
BROAD_WORDS = re.compile(r"\b(all|every|everything|entire|whole|any|recursive(ly)?|\*)\b", re.IGNORECASE)
AUTHORITY_CLAIM = re.compile(
    r"(ignore (all |any )?(previous|prior|above)|already (been )?(approved|authori[sz]ed)|"
    r"pre-?approved|you are now|system prompt|override (the )?(policy|rules)|admin(istrator)? (mode|override)|"
    r"no (need for|approval) (approval|needed|required))",
    re.IGNORECASE,
)
WILDCARD = re.compile(r"[*?\[\]]")
TRAVERSAL = re.compile(r"(^|[\\/])\.\.([\\/]|$)|^[\\/]|^[a-zA-Z]:|^~|\x00|%2e%2e", re.IGNORECASE)
INJECTION = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|rules)|system prompt|you are now|"
    r"APPROVE [0-9a-f-]{36}|disregard (the )?(policy|rules)|<\s*/?\s*(system|assistant)\s*>|"
    r"execute (this|the following) (command|shell))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Analysis:
    risk_level: str
    recommendation: str
    uncertainty: str
    findings: Tuple[RiskFinding, ...]
    summary: str


def _ev(text: str) -> str:
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[: MAX_EVIDENCE_CHARS - 1] + "…"


def _name(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _size(state) -> str:
    size = (state or {}).get("size")
    return f"{size} bytes" if isinstance(size, int) else "unknown size"


def analyze(req: RiskRequest) -> Analysis:
    findings: List[RiskFinding] = []
    uncertainty = 0  # 0 low, 1 medium, 2 high

    def add(code: str, severity: str, evidence: str) -> None:
        findings.append(RiskFinding(code=code, severity=severity, evidence=_ev(evidence)))

    op = req.operation.upper()
    target = req.target or ""
    protected = {p.lower() for p in req.protected_names}
    bound = bool(req.action_digest) and req.target_state is not None
    target_state = req.target_state or {}
    exists = bool(target_state.get("exists"))
    kind = target_state.get("kind")

    # Protected targets and sensitive-looking names
    for label, path in (("target", target), ("destination", req.destination or "")):
        if not path:
            continue
        name = _name(path)
        if name in protected:
            add("PROTECTED_TARGET", "CRITICAL", f"The {label} {name} is a protected resource.")
        elif SENSITIVE_NAME.search(name):
            add("SENSITIVE_NAME", "MEDIUM", f"The {label} name {name} looks like it may hold credentials.")

    # Paths that cannot be canonicalised inside the workspace
    if not bound:
        add("UNRESOLVED_TARGET", "CRITICAL",
            "The target could not be resolved to a path inside the workspace; its effect cannot be assessed.")
        uncertainty = 2

    # Destructive impact, from the state WARDEN observed before execution
    if bound and op == "DELETE":
        if not exists:
            add("UNCERTAIN_STATE", "LOW", f"{target} does not exist; the delete would change nothing.")
            uncertainty = max(uncertainty, 1)
        elif kind == "dir":
            add("DESTRUCTIVE_IMPACT", "HIGH", f"Deletes the directory {target} and everything in it.")
        else:
            add("DESTRUCTIVE_IMPACT", "HIGH", f"Permanently deletes {target} ({_size(target_state)}).")
    elif bound and op == "RENAME":
        dest_state = req.destination_state or {}
        if dest_state.get("exists"):
            add("DESTRUCTIVE_IMPACT", "HIGH",
                f"Renaming onto {req.destination} would replace an existing entry ({_size(dest_state)}).")
        else:
            add("DESTRUCTIVE_IMPACT", "MEDIUM", f"Moves {target} to {req.destination}; the original name disappears.")
        if not exists:
            add("UNCERTAIN_STATE", "LOW", f"{target} does not exist; the rename cannot succeed.")
            uncertainty = max(uncertainty, 1)
    elif bound and op == "WRITE" and exists:
        add("DESTRUCTIVE_IMPACT", "MEDIUM",
            f"Overwrites the existing {target} ({_size(target_state)}) with {req.content_length or 0} characters.")

    # Workspace escape attempts and link substitution
    raw = req.requested_target or target
    if TRAVERSAL.search(raw) or (req.destination and TRAVERSAL.search(req.destination)):
        add("PATH_TRAVERSAL", "CRITICAL" if not bound else "HIGH",
            "The requested path uses parent-directory, absolute or encoded segments to reach outside the workspace.")
    for label, state in (("target", target_state), ("destination", req.destination_state or {})):
        if state.get("kind") == "symlink":
            add("SYMLINK_TARGET", "HIGH", f"The {label} is a symbolic link; what it points to can change.")

    # Overwrite and collateral effects
    if bound and op == "WRITE" and exists:
        add("OVERWRITE", "MEDIUM", f"Replaces the current content of {target}; the old content is not kept.")
    if bound and op == "CREATE" and exists:
        add("UNCERTAIN_STATE", "LOW", f"{target} already exists; the create would fail.")
        uncertainty = max(uncertainty, 1)
    if bound and op == "RENAME" and req.destination:
        src_dir = target.replace("\\", "/").rpartition("/")[0]
        dst_dir = req.destination.replace("\\", "/").rpartition("/")[0]
        if src_dir != dst_dir:
            add("COLLATERAL_EFFECT", "LOW", f"Moves {target} into a different directory ({dst_dir or 'workspace root'}).")

    # Untrusted content that tries to steer agents
    if req.content_preview and INJECTION.search(req.content_preview):
        add("CONTENT_INJECTION", "HIGH",
            "The content to be written contains instructions aimed at agents (for example approval commands); "
            "it is treated as data only.")

    # Scope
    if WILDCARD.search(target):
        add("EXCESSIVE_SCOPE", "HIGH", f"The target {target} contains wildcard characters.")
    if target.strip() in {".", "./", ""} and op != "READ":
        add("EXCESSIVE_SCOPE", "CRITICAL", "The action targets the whole workspace.")
    if req.batch_size > 1 and op in DESTRUCTIVE:
        severity = "HIGH" if req.batch_size >= 3 else "MEDIUM"
        add("EXCESSIVE_SCOPE", severity,
            f"One instruction proposed {req.batch_size} actions; this is one of several destructive changes.")

    # Ambiguity: the target was inferred, or the request is phrased broadly
    text = req.request_text or ""
    if text and op != "READ":
        if _name(target) and _name(target) not in text.lower():
            add("AMBIGUOUS_REQUEST", "MEDIUM",
                f"The request did not name {_name(target)}; the target was inferred from the workspace.")
            uncertainty = max(uncertainty, 1)
        if BROAD_WORDS.search(text):
            add("AMBIGUOUS_REQUEST", "LOW", "The request uses broad wording (for example 'all' or 'everything').")
            uncertainty = max(uncertainty, 1)
    if text and AUTHORITY_CLAIM.search(text):
        add("AUTHORITY_CLAIM", "HIGH",
            "The request text claims prior approval or tries to override instructions; claims carry no authority.")

    findings = findings[:MAX_FINDINGS]
    rank = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    level = LEVEL_FOR_RANK[rank]
    unc = ("LOW", "MEDIUM", "HIGH")[uncertainty]
    top = max(findings, key=lambda f: SEVERITY_RANK[f.severity], default=None)
    summary = top.evidence if top else f"No risk indicators for {op} {target}."
    return Analysis(level, RECOMMENDATION[level], unc, tuple(findings), _ev(summary))
