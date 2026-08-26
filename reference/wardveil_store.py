"""Dependency-free append-only Wardveil record store and subscription reference."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from typing import Iterable

RETENTION_DAYS={"transient":1,"security_event":30,"incident_evidence":180,"audit_evidence":365}


def _canonical(value:object)->bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode()


def _parse(value:str)->datetime:
    parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)

@dataclass(frozen=True)
class StoredRecord:
    sequence:int
    stored_at:str
    retention_class:str
    expires_at:str
    record:dict
    digest:str

@dataclass
class Subscription:
    consumer_id:str
    cursor:int=0
    pending:dict[int,int]=field(default_factory=dict)
    dead_letters:list[dict]=field(default_factory=list)
    max_attempts:int=3

class AppendOnlyStore:
    def __init__(self)->None:
        self._entries:list[StoredRecord]=[]
        self._record_ids:set[str]=set()

    def append(self,record:dict,*,retention_class:str="security_event",now:datetime|None=None)->StoredRecord:
        now=now or datetime.now(timezone.utc)
        if retention_class not in RETENTION_DAYS:
            raise ValueError("unsupported_retention_class")
        if not isinstance(record,dict) or not record.get("record_id") or not record.get("correlation_id"):
            raise ValueError("invalid_record")
        producer=record.get("producer") or {}
        if producer.get("authoritative") is not True or not producer.get("id"):
            raise ValueError("non_authoritative_record")
        if record["record_id"] in self._record_ids:
            raise ValueError("duplicate_record_id")
        payload=dict(record)
        entry=StoredRecord(
            sequence=len(self._entries)+1,
            stored_at=now.isoformat(),
            retention_class=retention_class,
            expires_at=(now+timedelta(days=RETENTION_DAYS[retention_class])).isoformat(),
            record=payload,
            digest=sha256(_canonical(payload)).hexdigest(),
        )
        self._entries.append(entry)
        self._record_ids.add(record["record_id"])
        return entry

    def verify(self)->bool:
        return all(sha256(_canonical(e.record)).hexdigest()==e.digest for e in self._entries)

    def available(self,*,after_sequence:int=0,now:datetime|None=None)->tuple[StoredRecord,...]:
        now=now or datetime.now(timezone.utc)
        return tuple(e for e in self._entries if e.sequence>after_sequence and _parse(e.expires_at)>now)

    def enforce_retention(self,*,now:datetime|None=None)->int:
        now=now or datetime.now(timezone.utc)
        before=len(self._entries)
        self._entries=[e for e in self._entries if _parse(e.expires_at)>now]
        return before-len(self._entries)

    def rebuild_records(self,*,now:datetime|None=None)->tuple[dict,...]:
        return tuple(e.record for e in self.available(now=now))

class SubscriptionManager:
    def __init__(self,store:AppendOnlyStore)->None:
        self.store=store
        self.subscriptions:dict[str,Subscription]={}

    def subscribe(self,consumer_id:str,*,cursor:int=0,max_attempts:int=3)->Subscription:
        if not consumer_id or max_attempts<1:
            raise ValueError("invalid_subscription")
        sub=Subscription(consumer_id=consumer_id,cursor=cursor,max_attempts=max_attempts)
        self.subscriptions[consumer_id]=sub
        return sub

    def poll(self,consumer_id:str,*,limit:int=50,now:datetime|None=None)->tuple[StoredRecord,...]:
        sub=self.subscriptions[consumer_id]
        rows=self.store.available(after_sequence=sub.cursor,now=now)[:limit]
        for row in rows:
            sub.pending.setdefault(row.sequence,0)
        return rows

    def acknowledge(self,consumer_id:str,sequence:int)->None:
        sub=self.subscriptions[consumer_id]
        if sequence not in sub.pending:
            raise ValueError("sequence_not_pending")
        sub.pending.pop(sequence)
        if sequence==sub.cursor+1:
            sub.cursor=sequence
            while sub.cursor+1 not in sub.pending and any(e.sequence==sub.cursor+1 for e in self.store._entries):
                sub.cursor+=1

    def fail(self,consumer_id:str,sequence:int,reason:str)->None:
        sub=self.subscriptions[consumer_id]
        if sequence not in sub.pending:
            raise ValueError("sequence_not_pending")
        sub.pending[sequence]+=1
        if sub.pending[sequence]>=sub.max_attempts:
            entry=next((e for e in self.store._entries if e.sequence==sequence),None)
            sub.dead_letters.append({"sequence":sequence,"reason":reason,"record_id":entry.record["record_id"] if entry else None})
            sub.pending.pop(sequence)


def rebuild_security_center(store:AppendOnlyStore,*,now:datetime|None=None):
    from reference.wardveil_security_center import build_snapshot
    return build_snapshot(store.rebuild_records(now=now),now=now)
