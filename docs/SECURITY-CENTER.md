# Wardveil Security Center Reference Layer

Wardveil Security Center is the user/admin presentation and investigation layer for Wardveil Security. It consumes authoritative Wardveil runtime records and produces a conservative read model for protection status, threats, quarantine, incidents, and evidence.

## Rules

- Security Center is not an enforcement authority.
- It must not infer successful protection from a policy decision alone.
- Only authoritative runtime records are accepted into the reference snapshot.
- Failed, rejected, or expired protection actions degrade protection status.
- Unknown or unsupported scan coverage is never presented as clean or fully protected.
- Active likely/confirmed malicious findings and open incidents surface attention state.
- Quarantine remains a distinct review state and does not imply deletion.
- Incident closure is read from authoritative Response records; Security Center cannot manufacture closure.
- Evidence and operational state remain the basis for every protection claim.

## Reference statuses

- `unknown` — no authoritative records are available.
- `degraded` — evidence shows incomplete coverage or failed/rejected/expired protection.
- `attention` — active threats or incidents require attention.
- `protected` — at least one authoritative protection action is evidenced as successfully executed and no stronger negative condition is present.
- `operational` — authoritative security records exist without a stronger status, but this alone is not a claim that a specific protection action executed.

The reference implementation is intentionally dependency-free and is not itself a production dashboard, identity system, SIEM, policy executor, malware scanner, or incident-response authority.
