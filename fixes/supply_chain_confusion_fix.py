"""Defense-in-depth fix for issue #336: dependency confusion and typosquatting.

Dependency confusion happens when an internal package name can be resolved from
a public registry. Typosquatting happens when a dependency name is close enough
to a trusted package name that reviewers miss the difference. This module gives
CI a small policy gate for Python or npm-style dependency manifests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


PUBLIC_PYPI = "https://pypi.org/simple"
PUBLIC_NPM = "https://registry.npmjs.org"
HASH_PREFIX_RE = re.compile(r"^sha(256|384|512):[a-z0-9+/=_:-]{16,}$", re.IGNORECASE)
HASH_TOKEN_RE = re.compile(r"sha(?:256|384|512):[a-z0-9+/=_:-]{16,}", re.IGNORECASE)
PINNED_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+!_-]*$")


class SupplyChainSecurityError(ValueError):
    """Raised when a dependency policy check fails."""


@dataclass(frozen=True)
class DependencySpec:
    """Normalized dependency metadata used by the policy validator."""

    name: str
    version: str | None
    registry: str
    hashes: frozenset[str] = frozenset()
    ecosystem: str = "pypi"


@dataclass(frozen=True)
class DependencyPolicy:
    """Allowlist policy for dependency resolution."""

    allowed_public_registries: frozenset[str]
    private_registry: str
    internal_prefixes: frozenset[str]
    protected_names: frozenset[str]
    require_hashes: bool = True
    typo_distance: int = 1


def default_policy() -> DependencyPolicy:
    """Return a conservative policy for common Python/npm projects."""

    return DependencyPolicy(
        allowed_public_registries=frozenset({PUBLIC_PYPI, PUBLIC_NPM}),
        private_registry="https://packages.internal.example",
        internal_prefixes=frozenset({"internal-", "company-", "@company/"}),
        protected_names=frozenset({"django", "flask", "lodash", "requests", "react"}),
    )


def normalize_package_name(name: str) -> str:
    """Normalize package names before registry and typo checks."""

    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _base_name(name: str) -> str:
    normalized = normalize_package_name(name)
    if normalized.startswith("@") and "/" in normalized:
        return normalized.split("/", 1)[1]
    return normalized


def _registry_url(value: str) -> str:
    return value.rstrip("/").lower()


def _is_pinned(version: str | None) -> bool:
    if not version:
        return False
    if version.startswith((">", "<", "~", "^", "*")):
        return False
    return bool(PINNED_VERSION_RE.fullmatch(version))


def _has_valid_hash(hashes: Iterable[str]) -> bool:
    return any(HASH_PREFIX_RE.fullmatch(item.strip()) for item in hashes)


def _damerau_levenshtein(left: str, right: str) -> int:
    rows = len(left) + 1
    cols = len(right) + 1
    distances = [[0] * cols for _ in range(rows)]

    for row in range(rows):
        distances[row][0] = row
    for col in range(cols):
        distances[0][col] = col

    for row in range(1, rows):
        for col in range(1, cols):
            substitution_cost = 0 if left[row - 1] == right[col - 1] else 1
            distances[row][col] = min(
                distances[row - 1][col] + 1,
                distances[row][col - 1] + 1,
                distances[row - 1][col - 1] + substitution_cost,
            )
            if (
                row > 1
                and col > 1
                and left[row - 1] == right[col - 2]
                and left[row - 2] == right[col - 1]
            ):
                distances[row][col] = min(distances[row][col], distances[row - 2][col - 2] + 1)

    return distances[-1][-1]


def looks_like_typosquat(name: str, protected_names: Iterable[str], *, max_distance: int = 1) -> str | None:
    """Return the protected package name if ``name`` is suspiciously close."""

    candidate = _base_name(name)
    for protected in protected_names:
        trusted = _base_name(protected)
        if candidate == trusted:
            continue
        if _damerau_levenshtein(candidate, trusted) <= max_distance:
            return protected
    return None


def _as_spec(item: DependencySpec | Mapping[str, Any]) -> DependencySpec:
    if isinstance(item, DependencySpec):
        return item
    return DependencySpec(
        name=str(item.get("name") or ""),
        version=str(item["version"]) if item.get("version") is not None else None,
        registry=str(item.get("registry") or PUBLIC_PYPI),
        hashes=frozenset(str(value) for value in item.get("hashes") or []),
        ecosystem=str(item.get("ecosystem") or "pypi"),
    )


def _is_internal_package(name: str, policy: DependencyPolicy) -> bool:
    normalized = normalize_package_name(name)
    return any(normalized.startswith(prefix) for prefix in policy.internal_prefixes)


def validate_dependencies(
    dependencies: Iterable[DependencySpec | Mapping[str, Any]],
    *,
    policy: DependencyPolicy | None = None,
) -> None:
    """Raise when dependencies violate the supply-chain security policy."""

    active_policy = policy or default_policy()
    allowed_public = frozenset(_registry_url(url) for url in active_policy.allowed_public_registries)
    private_registry = _registry_url(active_policy.private_registry)

    errors: list[str] = []
    for raw_dependency in dependencies:
        dependency = _as_spec(raw_dependency)
        name = normalize_package_name(dependency.name)
        registry = _registry_url(dependency.registry)

        if not name:
            errors.append("dependency name is required")
            continue

        if not _is_pinned(dependency.version):
            errors.append(f"{dependency.name}: version must be exact-pinned")

        if active_policy.require_hashes and not _has_valid_hash(dependency.hashes):
            errors.append(f"{dependency.name}: trusted lock/hash entry is required")

        if _is_internal_package(name, active_policy):
            if registry != private_registry:
                errors.append(f"{dependency.name}: internal package must resolve from private registry")
        elif registry not in allowed_public:
            errors.append(f"{dependency.name}: registry is not allowlisted")

        protected_match = looks_like_typosquat(
            name,
            active_policy.protected_names,
            max_distance=active_policy.typo_distance,
        )
        if protected_match:
            errors.append(f"{dependency.name}: possible typosquat of {protected_match}")

    if errors:
        raise SupplyChainSecurityError("; ".join(errors))


def parse_pip_requirement(line: str, *, registry: str = PUBLIC_PYPI) -> DependencySpec | None:
    """Parse one simple requirements.txt line for CI validation."""

    cleaned = line.split("#", 1)[0].strip()
    if not cleaned or cleaned.startswith(("-r ", "--")):
        return None

    hash_values = frozenset(match.group(0) for match in HASH_TOKEN_RE.finditer(cleaned))
    requirement = cleaned.split("--hash", 1)[0].strip()
    name_match = re.match(r"^([A-Za-z0-9_.-]+)", requirement)
    if not name_match:
        return None

    name = name_match.group(1)
    version = None
    if "==" in requirement:
        version = requirement.split("==", 1)[1].strip().split()[0]

    return DependencySpec(name=name, version=version, registry=registry, hashes=hash_values)


def validate_pip_requirements(
    lines: Iterable[str],
    *,
    registry: str = PUBLIC_PYPI,
    policy: DependencyPolicy | None = None,
) -> None:
    """Validate simple requirements.txt lines with the same policy gate."""

    dependencies = [
        dependency
        for dependency in (parse_pip_requirement(line, registry=registry) for line in lines)
        if dependency is not None
    ]
    validate_dependencies(dependencies, policy=policy)


__all__ = [
    "DependencyPolicy",
    "DependencySpec",
    "SupplyChainSecurityError",
    "default_policy",
    "looks_like_typosquat",
    "normalize_package_name",
    "parse_pip_requirement",
    "validate_dependencies",
    "validate_pip_requirements",
]
