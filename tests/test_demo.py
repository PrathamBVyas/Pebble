"""The demo script is the six beats and nothing else."""

import os
import subprocess
import sys
from pathlib import Path


def test_demo_script():
    script = Path(__file__).with_name("demo.sh")
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
    for line in (
        "ciphertext",
        "fast-forward",
        "open refused",
        "receipt",
        "hidden",
        "old file opens",
        "new file rejected",
        "unshared folder never did",
        "restored grant list refused",
    ):
        assert line in completed.stdout
