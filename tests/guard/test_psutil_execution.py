"""Unit tests for psutil process tree termination in execution.py."""

import contextlib
import subprocess
import sys
import time

import psutil

from plugins.violin_guard import execution


def test_terminate_process_tree_with_psutil():
    # Spawn a python process that spawns a child process
    cmd = [
        sys.executable,
        "-c",
        "import subprocess, time; subprocess.Popen(['python', '-c', 'import time; time.sleep(60)']); time.sleep(60)",
    ]
    proc = subprocess.Popen(cmd)
    time.sleep(0.5)

    assert proc.poll() is None
    parent_ps = psutil.Process(proc.pid)
    children = parent_ps.children(recursive=True)
    assert len(children) >= 1

    # Terminate process tree
    execution._terminate_process(proc)

    # Verify both parent and child processes are dead
    assert proc.poll() is not None
    for child in children:
        with contextlib.suppress(psutil.NoSuchProcess, psutil.TimeoutExpired):
            child.wait(timeout=2.0)
        assert not child.is_running() or child.status() == psutil.STATUS_ZOMBIE
