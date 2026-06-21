"""Auto-discover Rule plugins.

Every module under ``argus.rules`` is imported; each concrete ``Rule`` subclass
found is instantiated once. Adding a detection = dropping a file in ``rules/``.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from argus.models import Rule


def discover_rules() -> list[Rule]:
    import argus.rules as rules_pkg

    found: list[Rule] = []
    seen: set[type] = set()
    for mod_info in pkgutil.iter_modules(rules_pkg.__path__):
        module = importlib.import_module(f"{rules_pkg.__name__}.{mod_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Rule)
                and obj is not Rule
                and obj.__module__ == module.__name__
                and obj not in seen
            ):
                seen.add(obj)
                found.append(obj())
    found.sort(key=lambda r: r.id)
    return found
