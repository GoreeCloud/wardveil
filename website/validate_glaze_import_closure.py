#!/usr/bin/env python3
"""Fail closed if Wardveil's locked GLAZE UI CSS graph is incomplete."""

from build import fetch_verified_glaze_assets

assets = fetch_verified_glaze_assets()
print(f"Validated locked GLAZE UI import closure across {len(assets)} Security Center stylesheets")
