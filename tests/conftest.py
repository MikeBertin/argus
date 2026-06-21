import sys
from pathlib import Path

# Make the package importable when pytest is run from anywhere.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PCAPS = ROOT / "fixtures" / "pcaps"
