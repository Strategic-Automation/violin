import sys
from pathlib import Path

# Make the repo's `scripts/` directory importable so `guard.*` submodules
# (e.g. guard.bootstrap) resolve in tests, mirroring how the CLI adds
# SCRIPTS_DIR to sys.path.
_ROOT = Path(__file__).resolve().parent.parent
# Repo root so `plugins.violin_guard` resolves as a package.
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
_SCRIPTS = _ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
