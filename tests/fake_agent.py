"""Stand-in 'agent' for testing the eval runner: writes secure code only when a Secure Vibe Coding pack is present."""
import shutil
import sys
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixtures"
cwd = Path.cwd()
has_pack = (cwd / "AGENTS.md").exists() or (cwd / ".claude" / "skills").exists()
shutil.copy(FIX / ("safe" if has_pack else "vulnerable") / "app.py", cwd / "app.py")
print("prompt was:", sys.argv[1][:40])
