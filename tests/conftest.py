import sys
from pathlib import Path

import pytest

# Make the package importable when pytest is run from anywhere.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PCAPS = ROOT / "fixtures" / "pcaps"


@pytest.fixture(scope="session", autouse=True)
def _ensure_generated_fixtures():
    """Generate the synthetic attack pcaps once per session, before any test
    module runs. Lives in conftest (not a test module) so it covers every module
    — `generated/` is gitignored, so on a clean checkout (e.g. CI) the files are
    absent and must be built first."""
    import fixtures.generate as gen

    gen.main()
