"""src/topic.py: one place that turns what the user typed into a CVE id or a technique id."""

import pytest

from src.topic import normalize_topic


@pytest.mark.parametrize(
    "text, expected",
    [
        ("cve-2021-44228", "CVE-2021-44228"),
        (" CVE-2021-44228 ", "CVE-2021-44228"),
        ("t1558.003", "T1558.003"),
        ("T1558", "T1558"),
        (" t1558.003 ", "T1558.003"),
    ],
)
def test_ids_are_normalized(text, expected):
    assert normalize_topic(text) == expected


@pytest.mark.parametrize("text", ["", "Kerberoasting", "T15", "T1558.3", "CVE-21-1", "../T1558.003"])
def test_anything_else_is_rejected(text):
    with pytest.raises(ValueError):
        normalize_topic(text)
