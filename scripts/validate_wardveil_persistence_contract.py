from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
doc=(ROOT/"PERSISTENCE.md").read_text()
source=(ROOT/"reference/wardveil_persistence.py").read_text()
required_doc=[
    "storage health", "does not", "encryption at rest", "backup", "checkpoint", "schema",
]
for token in required_doc:
    if token.lower() not in doc.lower():
        raise SystemExit(f"missing persistence contract token: {token}")
required_source=[
    "protection_claim", "checkpoint_regression", "unsupported_schema_version",
    "encryption_at_rest_not_configured", "recovery_unverified",
]
for token in required_source:
    if token not in source:
        raise SystemExit(f"missing persistence invariant: {token}")
print("Wardveil persistence contract validation passed.")
