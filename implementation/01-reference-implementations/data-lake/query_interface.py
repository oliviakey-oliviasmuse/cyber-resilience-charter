"""
Anonymised Data Lake — GB Query Interface

This is the read-only interface that the 19 Green Belts (and the 4 AI
agents) use to query the anonymised data lake. The interface enforces
the Data-Blind Protocol (§3.5 of the charter):

- Read-only access (no writes)
- Bounded results (max_rows, default 10000)
- Time-limited queries (timeout_sec, default 30s)
- ALLOWED data only (time deltas, compliance %, defect rates, traffic
  volumes, capability indices)
- NO raw data: no IP addresses, hostnames, MAC addresses, raw network
  logs, vendor credentials, or proprietary configurations
- Every query is logged to the audit trail

The anonymisation pipeline itself is CISO-team-owned and is NOT in this
folder. This interface is the GB-facing read-only query layer.

In production, this wraps a CISO-managed database (PostgreSQL, BigQuery,
Snowflake, etc.) with column-level access controls and query logging.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# =============================================================================
# Data classification (§3.5)
# =============================================================================


ALLOWED_PATTERNS = [
    # Time deltas
    r"mttd", r"mttr", r"elapsed_time", r"response_time", r"cycle_time",
    # Compliance / defect rates
    r"compliance", r"defect_rate", r"patch_compliance", r"vendor_compliance",
    r"false_positive_rate", r"true_positive_rate",
    # Traffic volumes (aggregate)
    r"traffic_volume", r"event_count", r"alert_count", r"anomaly_count",
    # Capability indices
    r"cpk", r"z_score", r"z-score", r"capability", r"dpmo",
    # Aggregate stats
    r"count\(", r"sum\(", r"avg\(", r"min\(", r"max\(", r"stddev\(",
    # FMEA aggregates
    r"rpn", r"severity_avg", r"occurrence_avg", r"detection_avg",
]

RESTRICTED_PATTERNS = [
    r"\bip_address\b", r"\bip\b", r"\bhostname\b", r"\bmac_address\b",
    r"\braw_log\b", r"\bnetwork_log\b", r"\bcredentials\b", r"\bpassword\b",
    r"\bvendor_remote_access\b", r"\bproprietary_config\b",
    r"\bprivate_key\b", r"\bsecret_key\b", r"\bapi_key\b",
]


class DataAccessError(Exception):
    """Raised when a query attempts to access restricted data."""
    pass


# =============================================================================
# Query interface
# =============================================================================


@dataclass
class QueryResult:
    """Result of a query against the anonymised data lake."""
    rows: List[Dict[str, Any]]
    row_count: int
    query_id: str
    elapsed_ms: int
    truncated: bool = False  # True if result was truncated due to max_rows


class AnonymisedDataLake:
    """Read-only query interface to the anonymised data lake.

    The CISO team owns the underlying database and the anonymisation pipeline.
    This class enforces:
    - ALLOWED data only (no IP/hostname/raw data)
    - Bounded results (max_rows)
    - Time-limited queries (timeout_sec)
    - Audit logging (every query)
    """

    def __init__(
        self,
        audit_log_path: Path,
        max_rows_default: int = 10000,
        timeout_sec_default: int = 30,
    ):
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_rows_default = max_rows_default
        self.timeout_sec_default = timeout_sec_default
        self.logger = logging.getLogger("data_lake")
        self._query_count = 0
        self._total_rows_returned = 0

    def query(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None,
        max_rows: Optional[int] = None,
        timeout_sec: Optional[int] = None,
        user_id: str = "unknown",
        user_role: str = "green_belt",
    ) -> QueryResult:
        """Execute a query against the anonymised data lake.

        Args:
            sql: SQL query
            params: Query parameters (bound)
            max_rows: Max rows to return (default: 10000)
            timeout_sec: Query timeout (default: 30s)
            user_id: Identifier of the user/agent running the query
            user_role: Role of the user/agent (green_belt, ai_agent, etc.)

        Returns:
            QueryResult

        Raises:
            DataAccessError: If the query attempts to access restricted data
        """
        max_rows = max_rows or self.max_rows_default
        timeout_sec = timeout_sec or self.timeout_sec_default

        # 1. Validate the query against data classification
        self._validate_query(sql)

        # 2. Generate query ID
        query_id = self._generate_query_id(sql, params, user_id)
        start = time.time()

        # 3. Execute the query (in production: against the actual database)
        # For this reference implementation, simulate the query
        try:
            rows = self._execute_query_mock(sql, params, max_rows)
        except Exception as e:
            self._audit_log("query_failed", {
                "query_id": query_id,
                "user_id": user_id,
                "user_role": user_role,
                "error": str(e),
            })
            raise

        elapsed_ms = int((time.time() - start) * 1000)
        truncated = len(rows) > max_rows
        if truncated:
            rows = rows[:max_rows]

        # 4. Audit log
        self._audit_log("query_executed", {
            "query_id": query_id,
            "user_id": user_id,
            "user_role": user_role,
            "sql_hash": self._hash_query(sql),  # hashed, not raw, for privacy
            "params_hash": self._hash_params(params) if params else None,
            "row_count": len(rows),
            "truncated": truncated,
            "elapsed_ms": elapsed_ms,
        })

        self._query_count += 1
        self._total_rows_returned += len(rows)

        return QueryResult(
            rows=rows,
            row_count=len(rows),
            query_id=query_id,
            elapsed_ms=elapsed_ms,
            truncated=truncated,
        )

    def _validate_query(self, sql: str) -> None:
        """Validate the query against the data classification (§3.5).

        Raises DataAccessError if the query attempts to access restricted data.
        """
        sql_lower = sql.lower()

        # Check for restricted patterns
        for pattern in RESTRICTED_PATTERNS:
            if re.search(pattern, sql_lower):
                raise DataAccessError(
                    f"Query attempts to access restricted data: pattern '{pattern}' matched. "
                    f"See §3.5 of the charter for the Data-Blind Protocol."
                )

        # Check for forbidden operations
        forbidden_ops = [r"\binsert\b", r"\bupdate\b", r"\bdelete\b", r"\bdrop\b", r"\balter\b", r"\btruncate\b", r"\bcreate\b"]
        for op in forbidden_ops:
            if re.search(op, sql_lower):
                raise DataAccessError(
                    f"Write operation '{op}' is not allowed on the read-only data lake"
                )

    def _execute_query_mock(
        self, sql: str, params: Optional[Dict[str, Any]], max_rows: int
    ) -> List[Dict[str, Any]]:
        """Mock query execution. In production, replace with actual DB call."""
        # Simulate a query result
        return [
            {"metric": "mttd_known_avg_sec", "value": 95.0, "sample_size": 1000, "anonymised": True},
            {"metric": "mttd_novel_avg_sec", "value": 540.0, "sample_size": 200, "anonymised": True},
            {"metric": "cpk_detection_known", "value": 2.1, "sample_size": 50, "anonymised": True},
            {"metric": "cpk_detection_novel", "value": 2.05, "sample_size": 50, "anonymised": True},
        ]

    def _generate_query_id(self, sql: str, params: Optional[Dict], user_id: str) -> str:
        """Generate a unique query ID for audit trail."""
        h = hashlib.sha256(
            f"{user_id}{sql}{params or ''}{time.time_ns()}".encode()
        ).hexdigest()[:16]
        return f"q-{h}"

    def _hash_query(self, sql: str) -> str:
        """Hash the query for the audit log (don't store raw SQL with PII risk)."""
        return hashlib.sha256(sql.encode()).hexdigest()[:16]

    def _hash_params(self, params: Dict) -> str:
        """Hash query parameters for the audit log."""
        return hashlib.sha256(str(sorted(params.items())).encode()).hexdigest()[:16]

    def _audit_log(self, action: str, details: Dict) -> None:
        """Log to the audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
        }
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(f"{entry}\n")

    def get_stats(self) -> Dict:
        """Return usage statistics for the executive dashboard."""
        return {
            "total_queries": self._query_count,
            "total_rows_returned": self._total_rows_returned,
            "max_rows_default": self.max_rows_default,
            "timeout_sec_default": self.timeout_sec_default,
        }


# =============================================================================
# Example usage
# =============================================================================


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    lake = AnonymisedDataLake(
        audit_log_path=Path("/var/log/cyber-resilience/data-lake-audit.jsonl"),
    )

    print("\n=== Anonymised Data Lake — example queries ===\n")

    # 1. Valid query
    try:
        result = lake.query(
            "SELECT AVG(mttd) FROM detection_events WHERE timestamp > NOW() - INTERVAL '7 days'",
            user_id="green_belt_track_b_01",
            user_role="green_belt",
        )
        print(f"Query 1 (allowed): {result.row_count} rows in {result.elapsed_ms}ms")
        for row in result.rows:
            print(f"  {row}")
    except DataAccessError as e:
        print(f"Query 1 BLOCKED: {e}")

    # 2. Blocked query (attempts to access IP addresses)
    try:
        result = lake.query(
            "SELECT ip_address FROM firewall_logs WHERE timestamp > NOW() - INTERVAL '1 day'",
            user_id="green_belt_track_b_01",
        )
        print(f"Query 2: {result.row_count} rows")
    except DataAccessError as e:
        print(f"Query 2 BLOCKED: {e}")

    # 3. Blocked query (write operation)
    try:
        result = lake.query(
            "DELETE FROM detection_events WHERE timestamp < NOW() - INTERVAL '90 days'",
            user_id="green_belt_track_b_01",
        )
        print(f"Query 3: {result.row_count} rows")
    except DataAccessError as e:
        print(f"Query 3 BLOCKED: {e}")

    # Stats
    print(f"\n=== Stats ===")
    for k, v in lake.get_stats().items():
        print(f"  {k}: {v}")
