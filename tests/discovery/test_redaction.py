from __future__ import annotations

import json

import pytest

from cver.discovery.llm.redaction import DataClass, sanitize_text


def test_internal_redacts_secrets_and_private_ip():
    payload = sanitize_text("token=abcdef 10.0.0.3 /home/alice/project", DataClass.INTERNAL)
    assert "abcdef" not in payload.text
    assert "10.0.0.3" not in payload.text
    assert payload.redactions >= 2


def test_confidential_is_abstract_only():
    payload = sanitize_text("secret source main.go\nconfig.yaml", DataClass.CONFIDENTIAL)
    value = json.loads(payload.text)
    assert value["note"] == "raw confidential content withheld by policy"
    assert "secret source" not in payload.text


def test_restricted_is_rejected():
    with pytest.raises(ValueError):
        sanitize_text("never transmit", DataClass.RESTRICTED)
