from datetime import datetime, timedelta, timezone
import os,sys
sys.path.insert(0,os.path.dirname(os.path.dirname(__file__)))
from reference.wardveil_store import AppendOnlyStore, SubscriptionManager, rebuild_security_center

NOW=datetime(2026,8,26,10,0,tzinfo=timezone.utc)

def record(record_id,record_type="protection_action",**extra):
    base={
        "record_id":record_id,"record_type":record_type,"correlation_id":"corr-1",
        "observed_at":NOW.isoformat(),"producer":{"id":"wardveil-test","authoritative":True},
        "scope":{"resource_type":"session","resource_id":"s1"},
    }
    base.update(extra)
    return base

store=AppendOnlyStore()
r1=store.append(record("r1",execution_status="succeeded",valid_until=(NOW+timedelta(minutes=15)).isoformat()),now=NOW)
r2=store.append(record("r2","audit_event",event_type="test",outcome="recorded"),retention_class="audit_evidence",now=NOW)
assert r1.sequence==1 and r2.sequence==2
assert store.verify()

try:
    store.append(record("r1"),now=NOW)
    raise AssertionError("duplicate record accepted")
except ValueError as exc:
    assert str(exc)=="duplicate_record_id"

subs=SubscriptionManager(store)
sub=subs.subscribe("security-center",max_attempts=2)
rows=subs.poll("security-center",now=NOW)
assert [r.sequence for r in rows]==[1,2]
assert sub.cursor==0
subs.acknowledge("security-center",1)
assert sub.cursor==1
subs.fail("security-center",2,"temporary")
assert not sub.dead_letters
subs.fail("security-center",2,"permanent")
assert sub.dead_letters[0]["record_id"]=="r2"

snapshot=rebuild_security_center(store,now=NOW)
assert snapshot.protection_status=="protected"

removed=store.enforce_retention(now=NOW+timedelta(days=2))
assert removed==1
assert [r.record["record_id"] for r in store.available(now=NOW+timedelta(days=2))]==["r2"]
assert store.verify()
print("Wardveil durable record store tests passed")
