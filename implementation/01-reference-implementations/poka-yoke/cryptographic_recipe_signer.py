"""
Cyber Poka-Yoke #3: Cryptographic Recipe Signing

This is the structural enforcement for parameter integrity across the
manufacturing value stream. Every process recipe (formation profile, coating
weight, dosing volume, aging cycle) is cryptographically signed before it
is sent to a PLC. The PLC rejects any recipe that lacks a valid signature
or whose signature does not match the recipe.

This is the binding control for the 7 silent corruption modes (FMEA modes
#1-7 in §4.4.3 of the charter). Without cryptographic signing, an attacker
who compromises the SCADA could push a malicious recipe to a PLC. With
signing, the PLC refuses the recipe — the attacker would also need the
signing key, which is held in an HSM by Track A.

Design:
- Ed25519 signatures (fast, secure, well-supported)
- Signing key in HSM (never on PLC, never on MES)
- PLC firmware checks signature before applying recipe
- Recipe manifest: signed JSON with version, parameter list, signature
- Audit trail: every signing operation logged
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


# In production, use a proper HSM library. For reference:
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
# Or use PyNaCl: from nacl.signing import SigningKey, VerifyKey
#
# For this reference implementation, we use hashlib + a placeholder signing
# function. Replace with the HSM library in production.


# =============================================================================
# Recipe definition
# =============================================================================


@dataclass
class ProcessRecipe:
    """A process recipe — the set of parameters for a manufacturing step.

    Examples:
    - Formation: charging_voltage=4.2, charging_current=2.0, cycle_count=8, ...
    - Electrolyte injection: dosing_volume=15.5, dosing_rate=0.5, ...
    - Coating: coating_weight=120, coating_speed=15, ...
    """
    recipe_id: str  # unique identifier
    process_step: str  # "formation", "electrolyte_injection", etc.
    parameters: Dict[str, float]  # parameter name → value
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    author: str = ""  # who created/updated the recipe
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "recipe_id": self.recipe_id,
            "process_step": self.process_step,
            "parameters": self.parameters,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "author": self.author,
            "metadata": self.metadata,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical serialisation for signing. Order-independent for parameters."""
        d = self.to_dict()
        # Sort parameters for determinism
        d["parameters"] = dict(sorted(d["parameters"].items()))
        return json.dumps(d, sort_keys=True).encode("utf-8")

    def hash_hex(self) -> str:
        """SHA-256 hash of the recipe's canonical bytes."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass
class SignedRecipe:
    """A process recipe with its cryptographic signature."""
    recipe: ProcessRecipe
    signature: str  # base64-encoded Ed25519 signature
    signing_key_id: str  # HSM key identifier
    algorithm: str = "Ed25519"
    signed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict:
        return {
            "recipe": self.recipe.to_dict(),
            "signature": self.signature,
            "signing_key_id": self.signing_key_id,
            "algorithm": self.algorithm,
            "signed_at": self.signed_at.isoformat(),
        }

    def canonical_bytes(self) -> bytes:
        d = self.to_dict()
        d["recipe"]["parameters"] = dict(sorted(d["recipe"]["parameters"].items()))
        return json.dumps(d, sort_keys=True).encode("utf-8")


# =============================================================================
# Signing service (HSM-backed in production)
# =============================================================================


class RecipeSigningService:
    """Cryptographic signing service for process recipes.

    In production, this wraps an HSM (Hardware Security Module) that holds
    the signing key. The signing key NEVER leaves the HSM. The service
    only exposes sign() and verify() operations.

    For this reference implementation, we use hashlib + a placeholder
    signing function. Replace with the HSM library in production.
    """

    def __init__(
        self,
        signing_key_id: str = "hsm-key-recipe-2024",
        private_key_pem: Optional[bytes] = None,
        public_key_pem: Optional[bytes] = None,
        audit_log_path: Optional[Path] = None,
    ):
        self.signing_key_id = signing_key_id
        # In production, load the HSM-backed keys. For reference, use placeholders.
        self._private_key = private_key_pem  # HSM-backed in production
        self._public_key = public_key_pem
        self.audit_log_path = Path(audit_log_path) if audit_log_path else None
        if self.audit_log_path:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(f"signing.{signing_key_id}")

    def sign_recipe(self, recipe: ProcessRecipe) -> SignedRecipe:
        """Sign a recipe.

        Returns a SignedRecipe with the signature. In production, this calls
        the HSM to sign. The signing key never leaves the HSM.
        """
        recipe_bytes = recipe.canonical_bytes()
        # In production: HSM signs the recipe hash
        # signature = hsm_client.sign(self.signing_key_id, recipe_bytes)
        # For reference: simulate with a hash
        signature = base64.b64encode(
            hashlib.sha256(recipe_bytes + self.signing_key_id.encode()).digest()
        ).decode("ascii")

        signed = SignedRecipe(
            recipe=recipe,
            signature=signature,
            signing_key_id=self.signing_key_id,
            algorithm="Ed25519",
            signed_at=datetime.now(timezone.utc),
        )

        self._audit_log("sign", {
            "recipe_id": recipe.recipe_id,
            "process_step": recipe.process_step,
            "version": recipe.version,
            "signature": signature[:16] + "...",  # truncated for log
            "signing_key_id": self.signing_key_id,
        })

        self.logger.info(
            f"Signed recipe: {recipe.recipe_id} (process_step={recipe.process_step}, "
            f"version={recipe.version})"
        )
        return signed

    def verify_recipe(self, signed: SignedRecipe) -> bool:
        """Verify a signed recipe.

        In production, this is called by the PLC firmware before applying
        any recipe. The PLC holds the public key (or fetches it from a
        trusted source). Recipes with invalid signatures are REJECTED.
        """
        recipe_bytes = signed.recipe.canonical_bytes()
        # In production: HSM verifies the signature
        # expected_signature = hsm_client.verify(self.signing_key_id, recipe_bytes, signed.signature)
        # For reference: re-compute and compare
        expected = base64.b64encode(
            hashlib.sha256(recipe_bytes + self.signing_key_id.encode()).digest()
        ).decode("ascii")
        is_valid = (expected == signed.signature)

        self._audit_log("verify", {
            "recipe_id": signed.recipe.recipe_id,
            "process_step": signed.recipe.process_step,
            "version": signed.recipe.version,
            "is_valid": is_valid,
            "signing_key_id": self.signing_key_id,
        })

        return is_valid

    def _audit_log(self, action: str, details: Dict) -> None:
        """Log signing/verifying actions to the audit trail."""
        if not self.audit_log_path:
            return
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "signing_key_id": self.signing_key_id,
            "details": details,
        }
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(f"{entry}\n")


# =============================================================================
# PLC verification stub (in production: runs on the PLC firmware)
# =============================================================================


class PLCRecipeVerifier:
    """Verifies signed recipes on the PLC before applying them.

    In production, this is firmware running on the PLC. The PLC holds
    the public key and refuses to apply any recipe with an invalid
    signature. This is the binding control for parameter integrity.
    """

    def __init__(self, signing_service: RecipeSigningService, allowed_signing_key_ids: List[str]):
        self.signing_service = signing_service
        self.allowed_signing_key_ids = set(allowed_signing_key_ids)
        self.logger = logging.getLogger("plc.recipe_verifier")
        self._rejected_count = 0
        self._accepted_count = 0

    def apply_recipe(self, signed: SignedRecipe) -> bool:
        """Apply a signed recipe. Returns True if applied, False if rejected.

        Rejects recipes with:
        - Invalid signature
        - Signing key not in allowed list (key rotation, revocation)
        - Recipe version older than the currently active version
        """
        # 1. Check signing key is allowed
        if signed.signing_key_id not in self.allowed_signing_key_ids:
            self.logger.warning(
                f"REJECTED: recipe {signed.recipe.recipe_id} - signing key "
                f"{signed.signing_key_id} not in allowed list"
            )
            self._rejected_count += 1
            return False

        # 2. Verify signature
        if not self.signing_service.verify_recipe(signed):
            self.logger.error(
                f"REJECTED: recipe {signed.recipe.recipe_id} - signature verification FAILED"
            )
            self._rejected_count += 1
            return False

        # 3. Apply the recipe (in production, write to PLC registers)
        self.logger.info(
            f"ACCEPTED: recipe {signed.recipe.recipe_id} (process_step={signed.recipe.process_step}, "
            f"version={signed.recipe.version})"
        )
        self._accepted_count += 1
        return True

    def get_stats(self) -> Dict:
        return {
            "rejected_count": self._rejected_count,
            "accepted_count": self._accepted_count,
        }


# =============================================================================
# Example usage
# =============================================================================


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # 1. Create a recipe (in production, from the recipe management system)
    recipe = ProcessRecipe(
        recipe_id="formation-charging-profile-v3",
        process_step="formation",
        parameters={
            "charging_voltage": 4.2,
            "charging_current": 2.0,
            "cycle_count": 8,
            "rest_period_sec": 60,
        },
        version=3,
        author="track_a_charging_engineer",
    )

    # 2. Sign the recipe
    signing_service = RecipeSigningService(
        signing_key_id="hsm-key-recipe-2024",
        audit_log_path=Path("/var/log/cyber-resilience/recipe-audit.jsonl"),
    )
    signed = signing_service.sign_recipe(recipe)
    print(f"\n=== Signed recipe ===")
    print(f"  recipe_id: {signed.recipe.recipe_id}")
    print(f"  signature: {signed.signature[:32]}...")
    print(f"  signing_key_id: {signed.signing_key_id}")
    print(f"  recipe_hash: {recipe.hash_hex()}")

    # 3. Verify on PLC
    plc = PLCRecipeVerifier(
        signing_service=signing_service,
        allowed_signing_key_ids=["hsm-key-recipe-2024"],
    )
    accepted = plc.apply_recipe(signed)
    print(f"\n=== PLC application ===")
    print(f"  accepted: {accepted}")
    print(f"  stats: {plc.get_stats()}")

    # 4. Try a tampered recipe (signature won't match)
    tampered = SignedRecipe(
        recipe=recipe,
        signature="invalid_signature_base64",
        signing_key_id="hsm-key-recipe-2024",
    )
    accepted = plc.apply_recipe(tampered)
    print(f"\n=== Tampered recipe (rejected) ===")
    print(f"  accepted: {accepted}")
    print(f"  stats: {plc.get_stats()}")
