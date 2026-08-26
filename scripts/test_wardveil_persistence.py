from datetime import datetime, timezone
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from reference.wardveil_persistence import InMemoryPersistenceAdapter

NOW=datetime(2026,8,26,10,25,tzinfo=timezone.utc)

def rec(record_id):
    return {
        "record_id":record_id,
        "record_type":"audit_event",
        "correlation_id":"corr-persist",
        "observed_at":NOW.isoformat(),
        "producer":{"id":"wardveil-test","authoritative":True},
        "scope":{"resource_type":"service","resource_id":"svc-1"},
        "event_type":"persistence_test","outcome":"recorded",
    }

adapter=InMemoryPersistenceAdapter()

tx=adapter.begin()
tx.append(rec("r1"),retention_class="audit_evidence")
tx.checkpoint("security-center",1)
created=tx.commit(now=NOW)
assert len(created)==1 and created[0].schema_version==1
assert adapter.records()[0]["record_id"]=="r1"
assert adapter.checkpoint("security-center").sequence==1

# A rejected transaction must not partially mutate state.
tx=adapter.begin()
tx.append(rec("r1"))
tx.checkpoint("security-center",2)
try:
    tx.commit(now=NOW)
    raise AssertionError("duplicate transaction accepted")
except ValueError as exc:
    assert str(exc)=="duplicate_record_id"
assert len(adapter.records())==1
assert adapter.checkpoint("security-center").sequence==1

# Checkpoints cannot regress.
tx=adapter.begin()
tx.checkpoint("security-center",0)
try:
    tx.commit(now=NOW)
    raise AssertionError("checkpoint regression accepted")
except ValueError as exc:
    assert str(exc)=="checkpoint_regression"

# Unsupported migration is fail closed.
try:
    adapter.migrate(2)
    raise AssertionError("unsupported migration accepted")
except ValueError as exc:
    assert str(exc)=="unsupported_schema_version"

health=adapter.health_evidence(now=NOW)
assert health.healthy is False
assert "encryption_at_rest_not_configured" in health.degraded_reasons
assert "backup_missing" in health.degraded_reasons
assert health.as_dict()["protection_claim"] is False

adapter.create_backup()
assert adapter.verify_backup_restore() is True
health=adapter.health_evidence(now=NOW)
assert health.backup_state=="available"
assert health.recovery_verification=="verified"
assert health.healthy is False  # passthrough encryption remains intentionally degraded

print("Wardveil persistence abstraction tests passed")
