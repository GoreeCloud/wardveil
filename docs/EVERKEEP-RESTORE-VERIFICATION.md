# Wardveil / Everkeep Restore Verification Handoff

Wardveil Security does not own backup, restore, or recovery verification. Everkeep is GoreeCloud's resilience and recovery authority. Wardveil may consume a bounded Everkeep restore-verification evidence record only to satisfy the `restore_verification_exercise` requirement in Wardveil's Cloudflare persistence runtime acceptance contract.

The machine-readable Wardveil consumer contract is `contracts/wardveil.everkeep.restore-verification.json`. Its accepted provider contract is Everkeep's `https://goreecloud.dev/everkeep/contracts/everkeep.restore-verification.v1.1.schema.json` version 1.1 from canonical repository `GoreeCloud/everkeep`. Wardveil adopted that version at Everkeep revision `4de9a3425215bbee5595eb929c1eb94d94d6f7b2`; the schema blob remains byte-identical (`158f2afe001be211d91ebfaa3e33c475849d53f9`) on verified canonical Everkeep main `f69e369e4d8627280fac728b7f7bcb02c43b5edd`. Everkeep's preserved v1.0 schema remains a provider compatibility artifact but no longer satisfies this Wardveil consumer gate.

## Required binding

A record is eligible only when it is for the production environment and identifies exactly:

- system: `Wardveil Security`
- component: `Cloudflare persistence runtime`
- resource: `goreecloud-wardveil-persistence`
- deployed revision: the exact 40-character lowercase hexadecimal Wardveil production revision being accepted.

Evidence from an older, newer, staging, unrelated, malformed, or ambiguously scoped target fails closed. A matching malformed revision string is not sufficient merely because caller and record happen to contain the same text.

## Required Everkeep evidence

Wardveil may mark only `restore_verification_exercise` passed when the provider record has `schemaVersion=1.1`, `status=pass`, `authoritative=true`, and its restore exercise proves isolated verification, integrity verification, restored-state verification, and non-empty evidence references. The restore timestamps must be timezone-qualified and represent a completed exercise according to Everkeep's contract.

The v1.1 record must include a timezone-qualified `freshUntil` deadline owned by Everkeep. The evidence is eligible only before that deadline, and `freshUntil` must be later than the evidence capture time. Missing, malformed, expired, future-captured, or internally impossible freshness evidence fails closed. Wardveil may shorten an Everkeep freshness window if a stricter future Wardveil acceptance policy requires it, but Wardveil must not extend, replace, or reinterpret Everkeep's producer-owned `freshUntil` deadline.

The evidence record must also preserve `securityStateAuthorityTransferred=false`. A record that claims security-authority transfer is ineligible even when its recovery exercise otherwise passed; Everkeep recovery evidence cannot manufacture Wardveil trust authority.

PITR availability is not restore verification. A Cloudflare bookmark, healthy storage backend, successful deployment, or successful Wardveil runtime probe cannot substitute for the Everkeep exercise.

## Authority boundary

Accepting Everkeep recovery evidence does not make Everkeep authoritative for Wardveil trust, authorization, detection, scan findings, policy decisions, protection execution, quarantine, incident state, or security presentation. It also does not make Wardveil a recovery authority.

Everkeep evidence can satisfy only the recovery-verification requirement named above. It cannot create, extend, reinterpret, or upgrade a `Protected by Wardveil` claim. Storage health and recovery health remain operational evidence rather than security-protection evidence.

## Provider evolution

Wardveil pins an explicitly accepted Everkeep provider-contract version. A newer Everkeep restore-verification contract is not implicitly accepted merely because the provider publishes it. Wardveil must deliberately update and validate its consumer contract after that provider version is authoritative and available. The same rule applies to any future v1.2 or later contract: this consumer remains pinned to v1.1 until another deliberate, independently validated adoption occurs.

## Final production acceptance

Wardveil Cloudflare persistence production acceptance remains fail closed. The runtime may move from `unaccepted` only when every required acceptance check is passed against the same exact deployed revision, including a current authoritative Everkeep restore-verification record accepted through this contract. A future Wardveil deployment requires new revision-bound evidence, and expired evidence cannot be reused to satisfy the recovery-verification requirement.
