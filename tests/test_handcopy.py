"""The hand-copy script is the checkpoint for the terminal vault."""

import os
import subprocess
import sys
from pathlib import Path


def test_handcopy_script():
    script = Path(__file__).with_name("handcopy.sh")
    env = os.environ.copy()
    env["PYTHON"] = sys.executable
    completed = subprocess.run(
        ["bash", str(script)],
        check=False,
        env=env,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"exit {completed.returncode}\n{completed.stdout}\n{completed.stderr}"
        )
    assert "handcopy ok" in completed.stdout
