"""Shared test fixtures — compiles test binaries if needed."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

CHALLENGES_DIR = os.path.join(os.path.dirname(__file__), "challenges")
RET2WIN_BIN = os.path.join(CHALLENGES_DIR, "ret2win_x64")


def _compile_if_missing(binary: str) -> str:
    """Compile test binaries via Make if they don't exist."""
    if not os.path.isfile(binary):
        result = subprocess.run(
            ["make", os.path.basename(binary)],
            cwd=CHALLENGES_DIR,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip(f"Cannot compile test binary: {result.stderr}")
    return binary


@pytest.fixture
def ret2win_binary() -> str:
    """Path to the compiled ret2win test binary."""
    return _compile_if_missing(RET2WIN_BIN)
