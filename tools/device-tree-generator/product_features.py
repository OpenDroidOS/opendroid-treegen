# Copyright 2026 OpenDroidOS
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Typed product feature catalogue and native product overrides."""

import json
from pathlib import Path


CATALOG_PATH = Path(__file__).parent / "runtime/product_features.json"
CATALOG = {item["id"]: item for item in json.loads(CATALOG_PATH.read_text(encoding="utf-8"))}


def validate(value):
    if not isinstance(value, dict):
        raise ValueError("product_features must be an object of Boolean choices")
    unknown = set(value) - set(CATALOG)
    if unknown:
        raise ValueError(f"Unknown product_features: {sorted(unknown)}")
    if any(type(choice) is not bool for choice in value.values()):
        raise ValueError("product_features values must be JSON Booleans")


def common_defaults():
    grouped = {}
    for item in CATALOG.values():
        grouped.setdefault((item["subsystem"], item["component"]), []).append(
            f'{item["feature"]} = {str(item["default"]).lower()}')
    return grouped
