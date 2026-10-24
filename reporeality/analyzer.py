"""Safe ZIP inspection and deterministic README claim verification."""

from __future__ import annotations

import json
import re
import tomllib
import zipfile
from dataclasses import asdict, dataclass
from difflib import get_close_matches
from io import BytesIO
from pathlib import PurePosixPath
from typing import Iterable

MAX_ARCHIVE_FILES = 5_000
MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024
MAX_FILE_SIZE = 5 * 1024 * 1024
TEXT_EXTENSIONS = {
    ".c", ".cfg", ".cpp", ".cs", ".css", ".dockerfile", ".env", ".go",
    ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx",
    ".kt", ".md", ".mjs", ".php", ".properties", ".py", ".rb", ".rs",
    ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx", ".txt", ".xml",
    ".yaml", ".yml",
}
MANIFEST_NAMES = {
    "requirements.txt", "pyproject.toml", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "go.mod", "cargo.toml", "composer.json",
    "gemfile", "pom.xml",
}
PATH_PATTERN = re.compile(
    r"(?<![\w])(?:\.{0,2}[\\/])?(?:[\w.@+-]+[\\/])*[\w.@+-]+\.[A-Za-z][\w-]*(?![\w])",
    re.IGNORECASE,
)
EXPLICIT_FILE_CONTEXT = re.compile(
    r"\b(?:file|path)\s*(?:named|called|:)?\s*[`'\"]?\s*$"
    r"|\b(?:the|this|following)\s+(?:source\s+)?file\s*:\s*[`'\"]?\s*$",
    re.IGNORECASE,
)
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
CONFIG_PATTERN = re.compile(r"(?<![A-Za-z0-9])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?![A-Za-z0-9])")
RUNTIME_PATTERN = re.compile(
    r"\b(Python|Node(?:\.js)?|Go|Rust)\s+(?:version\s+)?"
    r"(\d+(?:\.\d+){0,2})(?:\s*(?:or later|or newer|and later|\+))?",
    re.IGNORECASE,
)
COMMAND_PATTERN = re.compile(
    r"(?i)(?:^|\s)(pip(?:3)?\s+install\b[^\n`]*|"
    r"(?:python(?:3(?:\.\d+)?)?|py)\s+-m\s+pip\s+install\b[^\n`]*|"
    r"(?:npm|yarn|pnpm)\s+(?:install|i)\b[^\n`]*|"
    r"poetry\s+install\b[^\n`]*|uv\s+sync\b[^\n`]*|"
    r"go\s+mod\s+download\b[^\n`]*|cargo\s+build\b[^\n`]*|"
    r"composer\s+install\b[^\n`]*)"
)


class RepoArchiveError(ValueError):
    """An uploaded archive is invalid or exceeds safe inspection limits."""


@dataclass(frozen=True)
class ClaimResult:
    kind: str
    claim: str
    line: int
    status: str
    evidence: str
    correction: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RepositoryAnalysis:
    repository_name: str
    files: tuple[str, ...]
    readme_path: str | None
    claims: tuple[ClaimResult, ...]


def _safe_path(name: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"..", "."} for part in normalized.split("/"))
    ):
        raise RepoArchiveError(f"Unsafe archive path: {name}")
    return path.as_posix()


def _read_repository_archive(archive_bytes: bytes) -> tuple[dict[str, str], tuple[str, ...]]:
    """Read bounded archive paths and text files without extracting to disk."""
    try:
        archive = zipfile.ZipFile(BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError) as exc:
        raise RepoArchiveError("This file is not a valid ZIP archive.") from exc

    entries_to_read: list[tuple[zipfile.ZipInfo, str]] = []
    try:
        entries = archive.infolist()
        if len(entries) > MAX_ARCHIVE_FILES:
            raise RepoArchiveError(f"Archive contains more than {MAX_ARCHIVE_FILES:,} entries.")
        total_size = 0
        for entry in entries:
            if entry.is_dir():
                continue
            path = _safe_path(entry.filename)
            if entry.flag_bits & 0x1:
                raise RepoArchiveError(f"Encrypted files are not supported: {path}")
            if entry.file_size > MAX_FILE_SIZE:
                raise RepoArchiveError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB limit: {path}")
            total_size += entry.file_size
            if total_size > MAX_TOTAL_UNCOMPRESSED:
                raise RepoArchiveError("Archive exceeds the 50 MB uncompressed inspection limit.")
            entries_to_read.append((entry, path))

        metadata_files = {".ds_store", "thumbs.db", "desktop.ini"}
        project_roots = {
            PurePosixPath(path).parts[0]
            for _, path in entries_to_read
            if len(PurePosixPath(path).parts) > 1
            and PurePosixPath(path).parts[0].lower() not in metadata_files
        }
        has_root_files = any(
            len(PurePosixPath(path).parts) == 1
            and PurePosixPath(path).name.lower() not in metadata_files
            for _, path in entries_to_read
        )
        strip_root = next(iter(project_roots)) if len(project_roots) == 1 and not has_root_files else None
        normalized_entries = [
            (
                entry,
                path[len(strip_root) + 1:]
                if strip_root and PurePosixPath(path).parts[0] == strip_root and len(PurePosixPath(path).parts) > 1
                else path,
            )
            for entry, path in entries_to_read
        ]
        paths = tuple(sorted(path for _, path in normalized_entries))
        if len(paths) != len(set(paths)):
            raise RepoArchiveError("Archive contains duplicate file paths after project-folder normalization.")

        files: dict[str, str] = {}
        for entry, path in normalized_entries:
            if PurePosixPath(path).suffix.lower() not in TEXT_EXTENSIONS and PurePosixPath(path).name.lower() not in MANIFEST_NAMES:
                continue
            try:
                content = archive.read(entry).decode("utf-8-sig")
            except (UnicodeDecodeError, RuntimeError, zipfile.BadZipFile):
                continue
            files[path] = content
    except (OSError, RuntimeError) as exc:
        raise RepoArchiveError("The ZIP archive could not be read safely.") from exc
    finally:
        archive.close()
    return files, paths


def read_repository_archive(archive_bytes: bytes) -> dict[str, str]:
    """Read bounded text files from ZIP bytes without extracting to disk."""
    files, _ = _read_repository_archive(archive_bytes)
    return files


def _find_readme(files: dict[str, str]) -> str | None:
    root_readmes = [path for path in files if "/" not in path and PurePosixPath(path).name.lower() == "readme.md"]
    if root_readmes:
        return sorted(root_readmes)[0]
    readmes = [path for path in files if PurePosixPath(path).name.lower() == "readme.md"]
    return sorted(readmes, key=lambda path: (path.count("/"), path.lower()))[0] if readmes else None


def _dependency_names(files: dict[str, str]) -> tuple[dict[str, str], bool]:
    dependencies: dict[str, str] = {}
    supported = False

    def record(name: str, path: str) -> None:
        dependencies.setdefault(name.lower().replace("_", "-"), path)

    for path, content in files.items():
        name = PurePosixPath(path).name.lower()
        try:
            if name == "requirements.txt":
                supported = True
                for line in content.splitlines():
                    match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(?:[<>=!~;\[]|$)", line)
                    if match and not line.lstrip().startswith("#"):
                        record(match.group(1), path)
            elif name == "pyproject.toml":
                data = tomllib.loads(content)
                project = data.get("project", {})
                deps = project.get("dependencies", [])
                if isinstance(deps, list):
                    supported = True
                    for dependency in deps:
                        match = re.match(r"\s*([A-Za-z0-9_.-]+)", str(dependency))
                        if match:
                            record(match.group(1), path)
                poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                if isinstance(poetry, dict):
                    supported = True
                    for dep in poetry:
                        if dep.lower() != "python":
                            record(str(dep), path)
            elif name == "package.json":
                data = json.loads(content)
                for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    values = data.get(section, {})
                    if isinstance(values, dict):
                        supported = True
                        for dep in values:
                            record(str(dep), path)
            elif name == "go.mod":
                supported = True
                for line in content.splitlines():
                    if line.strip() and not line.lstrip().startswith(("module ", "go ", "require (", ")", "//")) and len(line.split()) >= 2 and "/" in line.split()[0]:
                        record(line.split()[0], path)
            elif name == "cargo.toml":
                data = tomllib.loads(content)
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    values = data.get(section, {})
                    if isinstance(values, dict):
                        supported = True
                        for dep in values:
                            record(str(dep), path)
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, AttributeError, TypeError):
            continue
    return dependencies, supported


def _expected_manifests(command: str) -> tuple[set[str], str] | None:
    lowered = command.lower()
    lowered = re.sub(r"^(?:python(?:3(?:\.\d+)?)?|py)\s+-m\s+", "", lowered)
    command = re.sub(r"^(?:python(?:3(?:\.\d+)?)?|py)\s+-m\s+", "", command, flags=re.IGNORECASE)
    if lowered.startswith(("pip install", "pip3 install")):
        if "-r " in lowered or "--requirement " in lowered:
            match = re.search(r"(?:-r|--requirement)\s+([^\s]+)", command, re.IGNORECASE)
            path = match.group(1).strip("\"'").replace("\\", "/") if match else ""
            while path.startswith("./"):
                path = path[2:]
            return ({path} if path else set(), "requirements file")
        return set(), "Python project manifest"
    if lowered.startswith(("npm install", "npm i")):
        return {"package.json"}, "Node.js package manifest"
    if lowered.startswith(("yarn install", "yarn i", "pnpm install", "pnpm i")):
        return {"package.json"}, "Node.js package manifest"
    if lowered.startswith("poetry install"):
        return {"pyproject.toml"}, "pyproject.toml"
    if lowered.startswith("uv sync"):
        return {"pyproject.toml"}, "pyproject.toml"
    if lowered.startswith("go mod download"):
        return {"go.mod"}, "go.mod"
    if lowered.startswith("cargo build"):
        return {"cargo.toml"}, "Cargo.toml"
    if lowered.startswith("composer install"):
        return {"composer.json"}, "composer.json"
    return None


def _suggest_manifest_command(files: dict[str, str]) -> str:
    names = {PurePosixPath(path).name.lower() for path in files}
    if "requirements.txt" in names:
        return "pip install -r requirements.txt"
    if "package.json" in names:
        return "npm install"
    if "pyproject.toml" in names:
        return "poetry install"
    if "go.mod" in names:
        return "go mod download"
    if "cargo.toml" in names:
        return "cargo build"
    if "composer.json" in names:
        return "composer install"
    return ""


def _verify_path(claim: str, files: dict[str, str]) -> tuple[str, str, str]:
    path_claim = claim.strip("`'\".,;:()[]{}")
    normalized = path_claim.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.strip("/")
    matches = [path for path in files if path == normalized]
    if matches:
        return "Verified", f"Found repository file: {matches[0]}", ""
    if "/" not in normalized:
        basename_matches = [
            path for path in files
            if PurePosixPath(path).name.lower() == normalized.lower()
        ]
        if len(basename_matches) == 1:
            return "Verified", f"Found unique repository file matching `{normalized}`: {basename_matches[0]}", ""
        if len(basename_matches) > 1:
            return "Unverified", f"`{normalized}` matches multiple archive files: {', '.join(basename_matches[:5])}. Specify a repository-relative path.", ""
    actual_paths = list(files)
    suggestions = get_close_matches(normalized, actual_paths, n=1, cutoff=0.78)
    correction = f"Did you mean `{suggestions[0]}`?" if suggestions else ""
    return "Failed", f"No archive file matches `{normalized}` after path normalization ({len(files)} archive files checked).", correction


def _documented_paths(line: str) -> list[str]:
    """Extract paths only from path-shaped references or explicit file markup."""
    candidates: list[str] = []
    for match in MARKDOWN_LINK.finditer(line):
        target = match.group(1).split("#", 1)[0].split("?", 1)[0]
        if target and not re.match(r"(?i)^(?:https?:|mailto:|#)", target):
            candidates.append(target)

    spans = [(match.start(1), match.group(1)) for match in re.finditer(r"`([^`]+)`", line)]
    spans.append((0, line))
    for span_start, span in spans:
        if COMMAND_PATTERN.search(span):
            continue
        for match in PATH_PATTERN.finditer(span):
            candidate = match.group(0)
            prefix = (line[:span_start] + span[:match.start()]).rstrip("`'\" ")
            has_path_structure = "/" in candidate or "\\" in candidate
            explicit_file_context = bool(EXPLICIT_FILE_CONTEXT.search(prefix))
            if has_path_structure or explicit_file_context:
                candidates.append(candidate)

    results: list[str] = []
    for candidate in candidates:
        candidate = candidate.strip().strip("<>\"'.,;:()[]{}")
        if not candidate or candidate.lower() == "readme.md":
            continue
        if candidate not in results:
            results.append(candidate)
    return results


def _runtime_evidence(runtime: str, version: str, files: dict[str, str]) -> tuple[str, str]:
    """Verify a runtime version only when a supported manifest states it exactly."""
    runtime = runtime.lower()
    for path, content in files.items():
        filename = PurePosixPath(path).name.lower()
        declared: list[str] = []
        if runtime == "python" and filename == "pyproject.toml":
            try:
                requires_python = tomllib.loads(content).get("project", {}).get("requires-python", "")
                declared.extend(re.findall(r"\d+(?:\.\d+){0,2}", str(requires_python)))
            except (tomllib.TOMLDecodeError, AttributeError, TypeError):
                continue
        elif runtime in {"node", "node.js"} and filename == "package.json":
            try:
                engines = json.loads(content).get("engines", {})
                node_engine = engines.get("node", "") if isinstance(engines, dict) else ""
                declared.extend(re.findall(r"\d+(?:\.\d+){0,2}", str(node_engine)))
            except (json.JSONDecodeError, AttributeError, TypeError):
                continue
        if version in declared:
            return "Verified", f"{path} declares the {runtime} version {version}."
        if declared:
            return "Unverified", f"{path} declares {runtime} version constraint(s) {', '.join(declared)}, which do not exactly establish README version {version}."
    return "Unverified", f"No supported manifest declares the {runtime} version {version}."


def analyze_repository(archive_bytes: bytes, repository_name: str = "Uploaded repository") -> RepositoryAnalysis:
    files, repository_paths = _read_repository_archive(archive_bytes)
    readme_path = _find_readme(files)
    if readme_path is None:
        return RepositoryAnalysis(repository_name, repository_paths, None, ())

    readme = files[readme_path]
    dependencies, has_dependency_manifest = _dependency_names(files)
    non_readme_contents = {
        path: text for path, text in files.items() if path != readme_path
    }
    claims: list[ClaimResult] = []
    seen: set[tuple[str, str, int]] = set()

    def add(kind: str, text: str, line: int, status: str, evidence: str, correction: str = "") -> None:
        key = (kind, text.strip(), line)
        if key not in seen:
            seen.add(key)
            claims.append(ClaimResult(kind, text.strip(), line, status, evidence, correction))

    for line_number, line in enumerate(readme.splitlines(), 1):
        for match in RUNTIME_PATTERN.finditer(line):
            runtime = match.group(1)
            version = match.group(2)
            status, evidence = _runtime_evidence(runtime, version, files)
            add("Runtime requirement", match.group(0), line_number, status, evidence)

        command_texts = [
            match.group(1)
            for code in re.findall(r"`([^`]+)`", line)
            for match in COMMAND_PATTERN.finditer(code)
        ]
        command_texts.extend(match.group(1) for match in COMMAND_PATTERN.finditer(line))
        for command_text in dict.fromkeys(command_texts):
            command = command_text.strip().rstrip(".,;")
            expectation = _expected_manifests(command)
            if expectation is None:
                add("Installation command", command, line_number, "Unverified", "Command is not in the supported deterministic checks.")
                continue
            expected, label = expectation
            expected_lower = {item.lower() for item in expected}
            matched_manifests = [
                path for path in repository_paths
                if path.lower() in expected_lower
                or (all("/" not in item for item in expected) and PurePosixPath(path).name.lower() in expected_lower)
            ]
            if not expected:
                add("Installation command", command, line_number, "Unverified", "The command does not name a repository manifest, so its success cannot be established from repository files alone.")
            elif any(path.lower() in expected_lower for path in matched_manifests):
                root_manifest = next(path for path in matched_manifests if path.lower() in expected_lower)
                add("Installation command", command, line_number, "Verified", f"Found required {label}: {root_manifest}.")
            elif matched_manifests:
                add("Installation command", command, line_number, "Unverified", f"Found {label} at {', '.join(matched_manifests)}, but the README command does not establish that it runs from that directory.")
            else:
                correction = _suggest_manifest_command(files)
                add("Installation command", command, line_number, "Failed", f"Required {label} `{', '.join(sorted(expected))}` is absent from {len(repository_paths)} normalized archive paths.", f"Repository evidence supports `{correction}`." if correction and correction != command else "")
            normalized_command = re.sub(r"^(?:python(?:3(?:\.\d+)?)?|py)\s+-m\s+", "", command, flags=re.IGNORECASE)
            for dependency in re.findall(r"(?:pip(?:3)?\s+install|npm\s+(?:install|i)|yarn\s+add|pnpm\s+add)\s+([A-Za-z0-9_.@/-]+)", normalized_command, re.IGNORECASE):
                package = dependency.split("==")[0].lower().replace("_", "-")
                if package.startswith("-"):
                    continue
                if not has_dependency_manifest:
                    add("Dependency", package, line_number, "Unverified", "No successfully parsed supported dependency manifest is available to check package declarations.")
                elif package in dependencies:
                    add("Dependency", package, line_number, "Verified", f"Declared in {dependencies[package]}.")
                else:
                    manifest_paths = [path for path in files if PurePosixPath(path).name.lower() in MANIFEST_NAMES]
                    add("Dependency", package, line_number, "Failed", f"`{package}` is not declared in inspected dependency manifest(s): {', '.join(manifest_paths)}.")

        for candidate in _documented_paths(line):
            if re.search(r"[*?{}]", candidate):
                add("File path", candidate, line_number, "Unverified", "The documented path contains a wildcard or placeholder and cannot be matched to one archive file.")
                continue
            status, evidence, correction = _verify_path(candidate, {path: "" for path in repository_paths})
            add("File path", candidate, line_number, status, evidence, correction)

        for match in CONFIG_PATTERN.finditer(line):
            variable = match.group(1)
            evidence_path = next(
                (path for path, text in non_readme_contents.items() if re.search(rf"(?<![A-Za-z0-9]){re.escape(variable)}(?![A-Za-z0-9])", text)),
                None,
            )
            if evidence_path:
                add("Configuration variable", variable, line_number, "Verified", f"Found `{variable}` in {evidence_path}.")
            else:
                inspected = ", ".join(list(non_readme_contents)[:3]) or "no non-README text files"
                remainder = " and others" if len(non_readme_contents) > 3 else ""
                add("Configuration variable", variable, line_number, "Unverified", f"No occurrence of `{variable}` was found in {len(non_readme_contents)} inspected text files (including {inspected}{remainder}); absence alone does not establish that it is unsupported.")

    claims.sort(key=lambda claim: (claim.line, claim.kind, claim.claim.lower()))
    return RepositoryAnalysis(repository_name, repository_paths, readme_path, tuple(claims))


def summarize_claims(claims: Iterable[ClaimResult]) -> dict[str, int]:
    counts = {"total": 0, "verified": 0, "failed": 0, "unverified": 0}
    for claim in claims:
        counts["total"] += 1
        counts[claim.status.lower()] += 1
    return counts
