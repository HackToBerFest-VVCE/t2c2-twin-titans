import io
import unittest
import zipfile

from reporeality.analyzer import (
    RepoArchiveError,
    analyze_repository,
    read_repository_archive,
    summarize_claims,
)


def make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


class ArchiveTests(unittest.TestCase):
    def test_invalid_zip_is_reported(self) -> None:
        with self.assertRaises(RepoArchiveError):
            read_repository_archive(b"not a zip")

    def test_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(RepoArchiveError):
            read_repository_archive(make_zip({"../outside.txt": "unsafe"}))

    def test_missing_readme_returns_empty_claims(self) -> None:
        result = analyze_repository(make_zip({"src/main.py": "print('safe')"}))
        self.assertIsNone(result.readme_path)
        self.assertEqual(result.claims, ())

    def test_single_top_level_project_folder_is_normalized(self) -> None:
        result = analyze_repository(make_zip({
            "demo-project/README.md": "See `src/main.py` and [logo](assets/logo.png).\n",
            "demo-project/src/main.py": "print('safe')\n",
            "demo-project/assets/logo.png": "binary placeholder",
            ".DS_Store": "archive metadata",
        }))
        self.assertEqual(result.readme_path, "README.md")
        self.assertIn("src/main.py", result.files)
        self.assertIn("assets/logo.png", result.files)
        path_claim = next(
            claim for claim in result.claims
            if claim.kind == "File path" and claim.claim == "src/main.py"
        )
        self.assertEqual(path_claim.status, "Verified")
        self.assertEqual(path_claim.evidence, "Found repository file: src/main.py")
        self.assertIn(
            ("assets/logo.png", "Verified"),
            {(claim.claim, claim.status) for claim in result.claims if claim.kind == "File path"},
        )


class VerificationTests(unittest.TestCase):
    def test_verifies_and_fails_readme_claims_with_evidence(self) -> None:
        repository = make_zip({
            "README.md": (
                "Run `pip install -r requirements.txt`.\n"
                "See `src/main.py` and `src/missing.py`.\n"
                "Set `APP_SECRET` before launch.\n"
            ),
            "requirements.txt": "requests>=2\n",
            "src/main.py": "APP_SECRET = ''\n",
        })
        result = analyze_repository(repository, "demo")
        by_claim = {(claim.kind, claim.claim): claim for claim in result.claims}
        self.assertEqual(by_claim[("Installation command", "pip install -r requirements.txt")].status, "Verified")
        self.assertEqual(by_claim[("File path", "src/main.py")].status, "Verified")
        self.assertEqual(by_claim[("File path", "src/missing.py")].status, "Failed")
        self.assertEqual(by_claim[("Configuration variable", "APP_SECRET")].status, "Verified")
        self.assertEqual(summarize_claims(result.claims)["total"], 4)

    def test_ordinary_os_executable_and_technology_mentions_are_not_paths(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "Use `python.exe` on Windows with Node.js and Git; Python is supported.\n",
        }))
        self.assertFalse([claim for claim in result.claims if claim.kind == "File path"])
        self.assertFalse([claim for claim in result.claims if claim.kind == "Runtime requirement"])
        self.assertFalse([claim for claim in result.claims if claim.kind == "Technology mention"])

    def test_executable_is_a_path_only_with_explicit_file_context(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "The file `python.exe` is included in this repository.\n",
            "bin/python.exe": "binary placeholder",
        }))
        path_claim = next(claim for claim in result.claims if claim.kind == "File path")
        self.assertEqual(path_claim.status, "Verified")
        self.assertEqual(path_claim.evidence, "Found unique repository file matching `python.exe`: bin/python.exe")

    def test_runtime_requirement_is_separate_from_technology_mentions(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "Requires Python 3.11 or later. Node.js is used for frontend tooling.\n",
            "pyproject.toml": '[project]\nrequires-python = ">=3.11"\n',
        }))
        runtime_claims = [claim for claim in result.claims if claim.kind == "Runtime requirement"]
        self.assertEqual(len(runtime_claims), 1)
        self.assertEqual(runtime_claims[0].status, "Verified")
        self.assertIn("pyproject.toml", runtime_claims[0].evidence)
        self.assertFalse([claim for claim in result.claims if claim.kind == "File path"])

    def test_runtime_requirement_without_manifest_evidence_is_unverified(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "Requires Python 3.12 or later.\n",
        }))
        claim = next(claim for claim in result.claims if claim.kind == "Runtime requirement")
        self.assertEqual(claim.status, "Unverified")
        self.assertIn("No supported manifest", claim.evidence)

    def test_missing_configuration_reference_is_unverified(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "Set `APP_SECRET` before starting.\n",
            "src/main.py": "print('ready')\n",
        }))
        claim = next(claim for claim in result.claims if claim.kind == "Configuration variable")
        self.assertEqual(claim.status, "Unverified")
        self.assertIn("src/main.py", claim.evidence)

    def test_windows_pip_command_and_manifest_path_are_verified(self) -> None:
        result = analyze_repository(make_zip({
            "demo/README.md": "In PowerShell, run `py -m pip install -r .\\requirements.txt`.\n",
            "demo/requirements.txt": "requests>=2\n",
        }))
        command = next(claim for claim in result.claims if claim.kind == "Installation command")
        self.assertEqual(command.status, "Verified")
        self.assertIn("requirements.txt", command.evidence)

    def test_nested_manifest_without_working_directory_context_is_unverified(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "Run `npm install`.\n",
            "frontend/package.json": '{"dependencies": {}}',
        }))
        command = next(claim for claim in result.claims if claim.kind == "Installation command")
        self.assertEqual(command.status, "Unverified")
        self.assertIn("frontend/package.json", command.evidence)

    def test_missing_file_reference_fails_with_archive_evidence(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "The file `src/not-there.py` contains the entry point.\n",
            "src/main.py": "print('safe')\n",
        }))
        claim = next(claim for claim in result.claims if claim.kind == "File path")
        self.assertEqual(claim.status, "Failed")
        self.assertIn("2 archive files checked", claim.evidence)

    def test_unrelated_command_is_not_reported_as_an_install_claim(self) -> None:
        result = analyze_repository(make_zip({"README.md": "Run `make magic`.\n"}))
        self.assertEqual(len(result.claims), 0)

    def test_dependency_claim_checks_manifest(self) -> None:
        result = analyze_repository(make_zip({
            "README.md": "Install with `pip install requests`.\n",
            "requirements.txt": "requests>=2\n",
        }))
        dependency = next(claim for claim in result.claims if claim.kind == "Dependency")
        self.assertEqual(dependency.status, "Verified")
        self.assertIn("requirements.txt", dependency.evidence)


if __name__ == "__main__":
    unittest.main()
