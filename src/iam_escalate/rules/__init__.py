"""Auto-import every rule module in this package so @register runs.

Drop a new my_technique.py in this folder and it's picked up with no
other wiring — that's the payoff of the plugin design.
"""

import importlib
import pkgutil

from .base import REGISTRY, Rule, register  # re-export

for _module in pkgutil.iter_modules(__path__):
    if _module.name != "base":
        importlib.import_module(f"{__name__}.{_module.name}")

__all__ = ["REGISTRY", "Rule", "register"]
