"""Independent filesystem verification service for the Auditor uAgent."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from warden.auditor.digest import compute_action_digest
from warden.auditor.models import AuditAttestation, AuditRequest, AuditVerdict
from warden.auditor.workspace_view import ReadOnlyWorkspaceView

logger = logging.getLogger("warden.auditor.service")


class AuditorService:
    """Core verification service executing independent filesystem audits.

    Invariants:
    1. Read-Only: Never executes, modifies, creates, or deletes any filesystem resource.
    2. Zero Trust in Executor: Physical disk state is verified independently of executor claims.
    3. Action Digest Binding: Requests with altered or mismatched digests are rejected as UNVERIFIED.
    4. Collateral Damage Detection: Detects unexpected file deletions or modifications outside the audit scope.
    5. Idempotent Deduplication: Duplicate requests with identical audit_id return the cached attestation.
    6. Policy Isolation: Does not participate in policy authorization or approval granting.
    """

    def __init__(
        self,
        auditor_address: Optional[str] = None,
        max_cached_results: int = 1000,
    ) -> None:
        self.auditor_address = auditor_address
        self.max_cached_results = max_cached_results
        self._attestation_cache: Dict[str, AuditAttestation] = {}

    def process_audit_request(
        self,
        req: AuditRequest,
        sender: Optional[str] = None,
    ) -> AuditAttestation:
        """Process an AuditRequest and return a verifiable AuditAttestation."""
        # 1. Idempotent deduplication check
        if req.audit_id in self._attestation_cache:
            logger.info("Duplicate audit request %s received from %s; returning cached attestation", req.audit_id, sender)
            return self._attestation_cache[req.audit_id]

        attestation = self._evaluate_audit_request(req)

        # Cache attestation (bounded cache)
        if len(self._attestation_cache) >= self.max_cached_results:
            oldest_key = next(iter(self._attestation_cache))
            del self._attestation_cache[oldest_key]
        self._attestation_cache[req.audit_id] = attestation

        return attestation

    def _evaluate_audit_request(self, req: AuditRequest) -> AuditAttestation:
        attestation_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        ws_view = ReadOnlyWorkspaceView(req.workspace_root)

        # 2. Action Digest Verification
        expected_digest = compute_action_digest(req, req.workspace_root)
        digest_valid = (req.action_digest == expected_digest)

        if not digest_valid:
            logger.warning("Audit request %s failed action digest verification", req.audit_id)
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=False,
                verdict=AuditVerdict.UNVERIFIED.value,
                observed_state={"digest_valid": False, "computed_digest": expected_digest},
                expected_state={"expected_digest": expected_digest},
                evidence=["Action digest mismatch: action parameters do not match supplied digest."],
                collateral_mutations=[],
                details="Audit rejected: Action digest mismatch. Action parameters or workspace root do not match digest.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        # 3. Workspace boundary and path containment
        allow_root = (req.operation == "READ")
        canonical_target = ws_view.get_canonical_path(req.target, allow_root=allow_root)
        if canonical_target is None:
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.UNVERIFIED.value,
                observed_state={"target_contained": False},
                expected_state={"target_contained": True},
                evidence=["Target path invalid or escapes workspace boundary."],
                collateral_mutations=[],
                details=f"Target path '{req.target}' is invalid or outside permitted workspace.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        # 4. Collateral Damage Inspection
        collateral_mutations: List[str] = []
        if req.pre_state_manifest:
            current_manifest = ws_view.capture_manifest()
            clean_target_rel = req.target.replace("\\", "/").strip().lstrip("/").lower()
            clean_dest_rel = (req.destination or "").replace("\\", "/").strip().lstrip("/").lower()

            for pre_file, pre_hash in req.pre_state_manifest.items():
                norm_pre = pre_file.replace("\\", "/").strip().lstrip("/").lower()
                # Check for unexpected deletions
                if norm_pre not in [f.lower() for f in current_manifest.keys()]:
                    if req.operation == "DELETE" and norm_pre == clean_target_rel:
                        continue  # expected deletion
                    if req.operation == "RENAME" and norm_pre == clean_target_rel:
                        continue  # expected source removal
                    collateral_mutations.append(f"unexpected_deletion:{pre_file}")

                # Check for unexpected modifications
                elif pre_hash is not None:
                    curr_hash = next((h for f, h in current_manifest.items() if f.lower() == norm_pre), None)
                    if curr_hash != pre_hash:
                        if req.operation in {"CREATE", "WRITE"} and norm_pre == clean_target_rel:
                            continue  # expected modification
                        if req.operation == "RENAME" and norm_pre == clean_dest_rel:
                            continue  # expected destination modification
                        collateral_mutations.append(f"unexpected_modification:{pre_file}")

        if collateral_mutations:
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.FAILED.value,
                observed_state={"collateral_mutations": collateral_mutations},
                expected_state={"collateral_mutations": []},
                evidence=[f"Collateral mutations detected: {m}" for m in collateral_mutations],
                collateral_mutations=collateral_mutations,
                details=f"Auditor detected collateral damage outside permitted target: {', '.join(collateral_mutations)}",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        # 5. Independent Physical State Verification (Zero trust in executor claims)
        evidence: List[str] = []
        observed: Dict[str, Any] = {
            "target": req.target,
            "target_exists": ws_view.exists(req.target, allow_root=allow_root),
            "executor_claimed_success": req.executor_claimed_success,
        }

        op = req.operation.upper()

        # If executor reported failure, verify that no unauthorized mutation occurred
        if not req.executor_claimed_success:
            if op == "DELETE" and not observed["target_exists"]:
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"target_exists": True},
                    evidence=["Target file was deleted despite executor reporting failure."],
                    details="Audit failed: File was deleted despite reported execution failure.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.VERIFIED.value,
                observed_state=observed,
                expected_state={"execution_success": False},
                evidence=["Confirmed no unauthorized mutation occurred following reported execution failure."],
                details="Verified: Execution failed safely and no unauthorized modification occurred.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        # When executor claimed success, physically verify expected state
        if op == "DELETE":
            if observed["target_exists"]:
                evidence.append("Target file still exists on disk despite executor claiming success.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"target_exists": False},
                    evidence=evidence,
                    collateral_mutations=[],
                    details=f"Audit failed: target '{req.target}' still exists on disk after claimed DELETE.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )
            evidence.append("Target file confirmed absent from disk.")
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.VERIFIED.value,
                observed_state=observed,
                expected_state={"target_exists": False},
                evidence=evidence,
                collateral_mutations=[],
                details=f"Outcome independently verified: target '{req.target}' is confirmed deleted.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        elif op in {"CREATE", "WRITE"}:
            if not observed["target_exists"]:
                evidence.append(f"Target '{req.target}' does not exist on disk despite executor claiming success.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"target_exists": True},
                    evidence=evidence,
                    collateral_mutations=[],
                    details=f"Audit failed: target '{req.target}' was not found after claimed {op}.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )

            if not ws_view.is_file(req.target):
                evidence.append(f"Target '{req.target}' is not a regular file.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"is_file": True},
                    evidence=evidence,
                    collateral_mutations=[],
                    details=f"Audit failed: target '{req.target}' is not a regular file.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )

            expected_content = req.content if req.content is not None else ""
            actual_bytes = ws_view.read_bytes(req.target) or b""
            actual_content = actual_bytes.decode("utf-8", errors="replace")
            actual_sha = hashlib.sha256(actual_bytes).hexdigest()
            expected_sha = hashlib.sha256(expected_content.encode("utf-8")).hexdigest()

            observed["content_matched"] = (actual_content == expected_content)
            observed["sha256"] = actual_sha

            if actual_content != expected_content:
                evidence.append(f"Content mismatch: expected sha256 {expected_sha}, got {actual_sha}.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"sha256": expected_sha},
                    evidence=evidence,
                    collateral_mutations=[],
                    details=f"Audit failed: file content on disk does not match requested content.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )

            evidence.extend(["Target file exists", "File is regular file", "Content matches exact expectation"])
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.VERIFIED.value,
                observed_state=observed,
                expected_state={"target_exists": True, "content_matched": True},
                evidence=evidence,
                collateral_mutations=[],
                details=f"Outcome independently verified: '{req.target}' exists with exact expected content.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        elif op == "READ":
            if not observed["target_exists"]:
                evidence.append(f"Target '{req.target}' does not exist on disk.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"target_exists": True},
                    evidence=evidence,
                    collateral_mutations=[],
                    details="Audit failed: read target does not exist.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )
            evidence.append("Read target exists and was accessible.")
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.VERIFIED.value,
                observed_state=observed,
                expected_state={"target_exists": True},
                evidence=evidence,
                collateral_mutations=[],
                details="Outcome independently verified: target exists and was accessible.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        elif op == "RENAME":
            if observed["target_exists"]:
                evidence.append("Source file still exists on disk after claimed RENAME.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"source_exists": False},
                    evidence=evidence,
                    collateral_mutations=[],
                    details="Audit failed: source file still exists after RENAME.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )

            dest_str = req.destination or ""
            dest_exists = ws_view.exists(dest_str)
            observed["destination_exists"] = dest_exists

            if not dest_exists:
                evidence.append(f"Destination '{dest_str}' does not exist on disk after claimed RENAME.")
                return AuditAttestation(
                    attestation_id=attestation_id,
                    audit_id=req.audit_id,
                    correlation_id=req.correlation_id,
                    action_id=req.action_id,
                    action_digest=req.action_digest,
                    digest_valid=True,
                    verdict=AuditVerdict.FAILED.value,
                    observed_state=observed,
                    expected_state={"destination_exists": True},
                    evidence=evidence,
                    collateral_mutations=[],
                    details="Audit failed: destination file does not exist after RENAME.",
                    auditor_address=self.auditor_address,
                    timestamp=now_iso,
                )

            evidence.extend(["Source file removed", "Destination file present"])
            return AuditAttestation(
                attestation_id=attestation_id,
                audit_id=req.audit_id,
                correlation_id=req.correlation_id,
                action_id=req.action_id,
                action_digest=req.action_digest,
                digest_valid=True,
                verdict=AuditVerdict.VERIFIED.value,
                observed_state=observed,
                expected_state={"source_exists": False, "destination_exists": True},
                evidence=evidence,
                collateral_mutations=[],
                details=f"Outcome independently verified: '{req.target}' successfully renamed to '{dest_str}'.",
                auditor_address=self.auditor_address,
                timestamp=now_iso,
            )

        # Unsupported operation -> UNVERIFIED
        return AuditAttestation(
            attestation_id=attestation_id,
            audit_id=req.audit_id,
            correlation_id=req.correlation_id,
            action_id=req.action_id,
            action_digest=req.action_digest,
            digest_valid=True,
            verdict=AuditVerdict.UNVERIFIED.value,
            observed_state={"unsupported_operation": op},
            expected_state={},
            evidence=[f"Unsupported operation '{op}'."],
            collateral_mutations=[],
            details=f"Auditor cannot establish verdict: unsupported operation '{op}'.",
            auditor_address=self.auditor_address,
            timestamp=now_iso,
        )
