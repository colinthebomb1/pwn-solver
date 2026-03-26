"""Tests for assistant text cleanup in agent.core."""

from agent.core import _sanitize_agent_text


def test_removes_empty_inline_code_pairs():
    assert _sanitize_agent_text("Buffer is `` (72 bytes)") == "Buffer is  (72 bytes)"
    assert _sanitize_agent_text("at ` ` here") == "at  here"
    assert _sanitize_agent_text("canary at ``\nnext") == "canary at \nnext"


def test_preserves_nonempty_inline_code():
    assert _sanitize_agent_text("use `gdb_find_offset`") == "use `gdb_find_offset`"
    assert _sanitize_agent_text("`0xdeadbeef`") == "`0xdeadbeef`"


def test_empty_input():
    assert _sanitize_agent_text("") == ""
