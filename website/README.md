# Wardveil Security Public Website

This directory contains the source for the planned public Wardveil Security website at `https://security.goreecloud.com`.

## Cloudflare Pages contract

- Repository: `GoreeCloud/goreecloud-wardveil-security`
- Production branch: `main`
- Root directory: repository root
- Build command: `python3 website/build.py`
- Build output directory: `website/dist`
- Planned custom domain: `security.goreecloud.com`

The build copies the approved canonical Wardveil identity from `branding/wardveil-security-icon.svg` into the isolated public artifact. The public site does not maintain or redraw a separate Wardveil mark.

## Validation

Run:

```bash
python3 website/validate.py
```

The validator checks the current machine-readable identity contract, requires approved visual/showcase state, verifies byte-identical canonical icon publication, enforces public security language, and checks the hardened Cloudflare Pages header contract.

## Public-information boundary

The website presents identity, security principles, normalized state semantics, relationship boundaries, and private reporting guidance. It must not expose internal topology, private hostnames or addresses, credentials, tokens, unrestricted diagnostics, sensitive monitoring evidence, or other operational information that is unnecessary for public understanding.

Only `website/dist` is intended for Pages publication. Connecting Cloudflare Pages, activating the custom domain, and changing DNS remain separate controlled production operations.
