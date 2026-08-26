# Wardveil / Everkeep Restore Verification Handoff

Wardveil Security does not own backup, restore, or recovery verification. Everkeep is GoreeCloud's resilience and recovery authority. Wardveil may consume a bounded Everkeep restore-verification evidence record only to satisfy the `restore_verification_exercise` requirement in Wardveil's Cloudflare persistence runtime acceptance contract.

The machine-readable Wardveil consumer contract is `contracts/wardveil.everkeep.restore-verification.json`. Its provider contract is Everkeep's `https://goreecloud.dev/everkeep/contracts/everkeep.restore-verification.schema.json` version 1.0.

## Required binding

A record is eligible only when it is for the production environment and identifies exactly:

- system: `Wardveil Security`
- component: `Cloudflare persistence runtime`
- resource: `goreecloud-wardveil-persistence`
- deployed revision: the exact 40-character Wardveil production revision being accepted.

Evidence from an older, newer, staging, unrelated, or ambiguously scoped target fails closed.

## Required Everkeep evidence

Wardveil may mark only `restore_verification_exercise` passed when the provider record has `status=pass`, `authoritative=true`, and its restore exercise proves isolated verification, integrity verification, restored-state verification, and non-empty evidence references. The restore timestamps must represent a completed exercise according to Everkeep's contract.

PITR availability is not restore verification. A Cloudflare bookmark, healthy storage backend, successful deployment, or successful Wardveil runtime probe cannot substitute for the Everkeep exercise.

## Authority boundary

Accepting Everkeep recovery evidence does not make Everkeep authoritative for Wardveil trust, authorization, detection, scan findings, policy decisions, protection execution, quarantine, incident state, or security presentation. It also does not make Wardveil a recovery authority.

Everkeep evidence can satisfy only the recovery-verification requirement named above. It cannot create, extend, reinterpret, or upgrade a `Protected by Wardveil` claim. Storage health and recovery health remain operational evidence rather than security-protection evidence.

## Final production acceptance

Wardveil Cloudflare persistence production acceptance remains fail closed. The runtime may move from `unaccepted` only when every required acceptance check is passed against the same exact deployed revision, including an authoritative Everkeep restore-verification record accepted through this contract. A future Wardveil deployment requires new revision-bound evidence.
