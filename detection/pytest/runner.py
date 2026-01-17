"""Minimal test runner providing a subset of pytest behavior."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterable, List


@dataclass
class TestCase:
    module: ModuleType
    callable: Callable[[], None]
    name: str
    nodeid: str


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pytest", add_help=True)
    parser.add_argument("paths", nargs="*", default=["tests"])
    args = parser.parse_args(list(argv) if argv is not None else None)

    test_cases: List[TestCase] = []
    for item in args.paths:
        path = Path(item)
        if path.is_dir():
            test_cases.extend(_discover_directory(path))
        elif path.is_file() and path.suffix == ".py":
            test_cases.extend(_discover_file(path))
        else:
            print(f"pytest: warning: ignoring {item}")

    if not test_cases:
        print(
            "============================= no tests ran ============================="
        )
        return 5

    failures = 0
    print(f"collected {len(test_cases)} item(s)")
    for case in test_cases:
        try:
            case.callable()
        except AssertionError as exc:  # pragma: no cover - simple formatter
            failures += 1
            print(f"FAILED {case.nodeid}\n  AssertionError: {exc}")
        except Exception as exc:  # pragma: no cover
            failures += 1
            print(f"FAILED {case.nodeid}\n  {exc.__class__.__name__}: {exc}")
        else:
            print(f"PASSED {case.nodeid}")

    if failures:
        print(
            f"========================= {failures} failed, {len(test_cases) - failures} passed ========================="
        )
        return 1
    print(
        f"========================= {len(test_cases)} passed ========================="
    )
    return 0


def _discover_directory(directory: Path) -> List[TestCase]:
    cases: List[TestCase] = []
    for path in sorted(directory.rglob("test_*.py")):
        cases.extend(_discover_file(path))
    return cases


def _discover_file(path: Path) -> List[TestCase]:
    module = _load_module(path)
    cases: List[TestCase] = []

    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and name.startswith("test_"):
            cases.append(
                TestCase(
                    module=module,
                    callable=obj,
                    name=name,
                    nodeid=f"{path.name}::{name}",
                )
            )
        elif inspect.isclass(obj) and name.startswith("Test"):
            for method_name, method in inspect.getmembers(obj, inspect.isfunction):
                if method_name.startswith("test_"):
                    instance = obj()
                    cases.append(
                        TestCase(
                            module=module,
                            callable=getattr(instance, method_name),
                            name=method_name,
                            nodeid=f"{path.name}::{name}::{method_name}",
                        )
                    )
    return cases


def _load_module(path: Path) -> ModuleType:
    module_name = path.stem
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot import test module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
