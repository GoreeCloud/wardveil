# Execution Reconciliation

Wardveil durable execution claims deliberately block blind retries when an action may have occurred but a durable receipt is unavailable. `reference/wardveil_execution_reconciliation.py` adds an evidence-bound reconciliation record for that uncertain state.

A reconciliation record binds the original authorization digest, nonce, executor, action, scope, and idempotency key to an observed outcome, an evidence reference, an actor identity, and a reconciliation timestamp. Supported observations are `succeeded`, `failed`, `not_executed`, and `unknown`.

Reconciliation never invokes the executor and never makes the original authorization reusable. `not_executed` explicitly requires a new authorization before a future execution attempt. `unknown` leaves the effective state as `execution_reconciliation_required`. A known outcome records the operator/evidence conclusion but does not synthesize a missing protection receipt.

This is a source-level reconciliation model. Production use still requires an authenticated reconciliation authority, durable append-only storage, evidence retention policy, runtime integration, and acceptance evidence for the deployed executor path.
