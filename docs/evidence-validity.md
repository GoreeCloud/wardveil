# Wardveil Security Evidence Validity

A current `protected` Wardveil Security claim requires current authoritative evidence with a producer- or applicable-policy-defined validity deadline.

`valid_until` is part of the evidence boundary for protected status. Missing or expired required validity cannot support `protected` or `protected_by_wardveil: true`. Consumers may evaluate the deadline but may not extend, replace, or override it.

This contract preserves Wardveil Security authority for security state, evidence semantics, and protection presentation. It does not create runtime acceptance, production approval, deployment authorization, release authorization, or Stable qualification.
