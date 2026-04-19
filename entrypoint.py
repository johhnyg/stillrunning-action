#!/usr/bin/env python3
"""
stillrunning GitHub Action v3 — Supply chain attack protection.

New in v3:
- Blocklist check first (fast, free)
- Yanked package detection
- Community reporting of DANGEROUS packages
- Clean summary output
"""
import ast
import glob
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

API_BASE = "https://stillrunning.io"
PYPI_URL = "https://pypi.org/pypi"


def parse_requirements_txt(content: str) -> list:
    """Parse requirements.txt format."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "#" in line:
            line = line.split("#")[0].strip()
        if line:
            packages.append(line)
    return packages


def parse_package_json(content: str) -> list:
    """Parse package.json dependencies."""
    packages = []
    try:
        data = json.loads(content)
        for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
            deps = data.get(dep_type, {})
            for name, version in deps.items():
                version = re.sub(r'^[\^~>=<]', '', str(version))
                packages.append(f"{name}@{version}")
    except json.JSONDecodeError:
        pass
    return packages


def parse_pyproject_toml(content: str) -> list:
    """Parse pyproject.toml dependencies."""
    packages = []
    in_deps = False
    for line in content.splitlines():
        line_stripped = line.strip()
        if line_stripped == "[project.dependencies]" or line_stripped == "dependencies = [":
            in_deps = True
            continue
        if in_deps:
            if line_stripped.startswith("[") or (line_stripped == "]"):
                in_deps = False
                continue
            if "=" in line_stripped or line_stripped.startswith('"'):
                pkg = line_stripped.strip('",[] ')
                pkg = re.split(r'[>=<\[\]]', pkg)[0].strip()
                if pkg and not pkg.startswith("#"):
                    packages.append(pkg)
    return packages


def parse_pipfile(content: str) -> list:
    """Parse Pipfile packages section."""
    packages = []
    in_packages = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[packages]" or line == "[dev-packages]":
            in_packages = True
            continue
        if line.startswith("[") and in_packages:
            in_packages = False
            continue
        if in_packages and "=" in line:
            name = line.split("=")[0].strip().strip('"')
            if name:
                packages.append(name)
    return packages


def extract_imports_from_file(filepath: Path) -> set:
    """Extract import statements from Python file using AST."""
    imports = set()
    try:
        content = filepath.read_text()
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".")[0]
                    imports.add(module)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module = node.module.split(".")[0]
                    imports.add(module)
    except Exception:
        pass
    return imports


def find_python_imports(patterns: list, workspace: str) -> set:
    """Find all imports in Python files matching patterns."""
    all_imports = set()
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        full_pattern = os.path.join(workspace, pattern)
        for filepath in glob.glob(full_pattern, recursive=True):
            if os.path.isfile(filepath):
                imports = extract_imports_from_file(Path(filepath))
                all_imports.update(imports)

    # Filter out standard library
    stdlib = {
        "abc", "argparse", "ast", "asyncio", "base64", "collections",
        "concurrent", "configparser", "contextlib", "copy", "csv", "dataclasses",
        "datetime", "decimal", "difflib", "email", "enum", "functools", "gc",
        "glob", "gzip", "hashlib", "heapq", "hmac", "html", "http", "importlib",
        "inspect", "io", "itertools", "json", "logging", "math", "multiprocessing",
        "operator", "os", "pathlib", "pickle", "platform", "pprint", "queue",
        "random", "re", "secrets", "select", "shutil", "signal", "socket", "sqlite3",
        "ssl", "statistics", "string", "struct", "subprocess", "sys", "tarfile",
        "tempfile", "textwrap", "threading", "time", "traceback", "types", "typing",
        "unittest", "urllib", "uuid", "warnings", "weakref", "xml", "zipfile", "zlib",
        "_thread", "builtins", "codecs", "locale", "fnmatch", "stat", "errno",
    }
    return all_imports - stdlib


def check_blocklist(package: str) -> dict:
    """Check if package is in stillrunning blocklist (v3 - fast, free)."""
    try:
        url = f"{API_BASE}/api/blocklist/{package.lower()}"
        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning-action/3.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("blocked"):
                entries = data.get("entries", [])
                reason = entries[0].get("reason", "Known malicious") if entries else "Known malicious"
                return {"blocked": True, "reason": reason, "source": "blocklist"}
            return {"blocked": False}
    except Exception:
        return {"blocked": False, "error": True}


def check_pypi_yanked(package: str, version: str = None) -> dict:
    """Check if package was yanked from PyPI (v3)."""
    try:
        url = f"{PYPI_URL}/{package}/json"
        if version:
            url = f"{PYPI_URL}/{package}/{version}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning-action/3.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        # Check if yanked
        releases = data.get("releases", {})
        pkg_version = version or data.get("info", {}).get("version", "")
        if pkg_version and pkg_version in releases:
            version_files = releases[pkg_version]
            if version_files and all(f.get("yanked", False) for f in version_files):
                return {"yanked": True, "version": pkg_version}
        return {"yanked": False, "exists": True}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"yanked": False, "exists": False, "reason": "Not found on PyPI"}
        return {"yanked": False, "error": True}
    except Exception:
        return {"yanked": False, "error": True}


def report_dangerous_package(package: str, version: str, reason: str, repo: str):
    """Report DANGEROUS package to stillrunning.io blocklist (v3)."""
    try:
        url = f"{API_BASE}/api/threats/report"
        payload = json.dumps({
            "package": package,
            "version": version,
            "ecosystem": "pip" if "@" not in package else "npm",
            "reason": reason,
            "reporter": f"github-action:{repo}",
            "source": "github_action_v3"
        }).encode()
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "User-Agent": "stillrunning-action/3.0"
        })
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass  # Best effort


def call_api(packages: list, token: str, repo: str, imports: list = None) -> dict:
    """Call stillrunning.io API for AI scanning."""
    payload = json.dumps({
        "packages": packages,
        "imports": imports or [],
        "repo": repo,
        "token": token,
        "version": "3.0"
    }).encode()
    req = urllib.request.Request(
        f"{API_BASE}/api/github-action/scan",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "stillrunning-action/3.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def find_and_parse_files(file_patterns: list) -> list:
    """Find and parse dependency files."""
    packages = []
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    for pattern in file_patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        path = Path(workspace) / pattern
        if path.exists():
            content = path.read_text()
            if pattern.endswith(".txt"):
                packages.extend(parse_requirements_txt(content))
            elif pattern.endswith(".json"):
                packages.extend(parse_package_json(content))
            elif pattern == "Pipfile":
                packages.extend(parse_pipfile(content))
            elif pattern.endswith(".toml"):
                packages.extend(parse_pyproject_toml(content))
    return list(set(packages))


def post_pr_comment(comment: str):
    """Post comment to PR using GitHub API."""
    github_token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not github_token or not event_path:
        return
    try:
        with open(event_path) as f:
            event = json.load(f)
        pr_number = event.get("pull_request", {}).get("number") or event.get("issue", {}).get("number")
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        if not pr_number or not repo:
            return
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        payload = json.dumps({"body": comment}).encode()
        req = urllib.request.Request(url, data=payload, headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "stillrunning-action/3.0"
        })
        urllib.request.urlopen(req, timeout=30)
    except Exception:
        pass


def set_output(name: str, value: str):
    """Set GitHub Actions output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def print_summary(results: dict, packages_count: int, imports_count: int):
    """Print clean summary (v3)."""
    print("")
    print("=" * 40)
    print("stillrunning Security Report")
    print("=" * 40)
    print("")

    clean = results.get("clean", 0)
    suspicious = results.get("suspicious", 0)
    dangerous = results.get("dangerous", 0)
    blocklist_hits = results.get("blocklist_hits", 0)
    yanked = results.get("yanked", 0)

    if dangerous == 0 and suspicious == 0 and blocklist_hits == 0 and yanked == 0:
        print(f"  Packages checked: {packages_count}")
        if imports_count > 0:
            print(f"  Imports scanned: {imports_count}")
        print(f"  All packages clean")
    else:
        print(f"  Packages checked: {packages_count}")
        if imports_count > 0:
            print(f"  Imports scanned: {imports_count}")
        print(f"  Suspicious (review): {suspicious}")
        print(f"  Dangerous (blocked): {dangerous}")
        print(f"  Blocklist hits: {blocklist_hits}")
        if yanked > 0:
            print(f"  Yanked packages: {yanked}")

    # Print dangerous details
    for pkg_info in results.get("dangerous_details", []):
        print("")
        print(f"  BLOCKED: {pkg_info['package']}")
        if pkg_info.get("score"):
            print(f"     Score: {pkg_info['score']}/100")
        print(f"     Reason: {pkg_info.get('reason', 'Known malicious')}")
        print(f"     Action: Remove from requirements.txt")

    print("")
    print("=" * 40)


def main():
    args = sys.argv[1:] if len(sys.argv) > 1 else []
    token = args[0] if len(args) > 0 else os.environ.get("INPUT_TOKEN", "")
    files = args[1] if len(args) > 1 else os.environ.get("INPUT_FILES", "requirements.txt")
    fail_dangerous = (args[2] if len(args) > 2 else os.environ.get("INPUT_FAIL-ON-DANGEROUS", "true")).lower() == "true"
    fail_suspicious = (args[3] if len(args) > 3 else os.environ.get("INPUT_FAIL-ON-SUSPICIOUS", "false")).lower() == "true"
    comment_pr = (args[4] if len(args) > 4 else os.environ.get("INPUT_COMMENT-ON-PR", "true")).lower() == "true"
    scan_imports = (args[5] if len(args) > 5 else os.environ.get("INPUT_SCAN-IMPORTS", "true")).lower() == "true"
    python_paths = args[6] if len(args) > 6 else os.environ.get("INPUT_PYTHON-PATHS", "**/*.py")
    verify_hashes = (args[7] if len(args) > 7 else os.environ.get("INPUT_VERIFY-HASHES", "true")).lower() == "true"

    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")

    print("[stillrunning] Security Scan v3")
    print("")

    # Parse dependency files
    file_list = [f.strip() for f in files.split(",")]
    packages = find_and_parse_files(file_list)
    print(f"[stillrunning] Found {len(packages)} packages in dependency files")

    # Scan Python imports
    imports = []
    if scan_imports:
        path_list = [p.strip() for p in python_paths.split(",")]
        imports = list(find_python_imports(path_list, workspace))
        print(f"[stillrunning] Found {len(imports)} unique imports")

    all_packages = list(set(packages + imports))
    if not all_packages:
        print("[stillrunning] No packages to scan")
        set_output("result", "pass")
        set_output("dangerous-count", "0")
        set_output("suspicious-count", "0")
        return 0

    # Results tracking
    results = {
        "clean": 0,
        "suspicious": 0,
        "dangerous": 0,
        "blocklist_hits": 0,
        "yanked": 0,
        "dangerous_details": []
    }
    packages_to_ai_scan = []

    # STEP 1: Check blocklist first (fast, free)
    print(f"\n[stillrunning] Checking blocklist...")
    for pkg in all_packages:
        pkg_name = re.split(r'[>=<\[\]@==]', pkg)[0].strip().lower()
        if not pkg_name:
            continue

        bl = check_blocklist(pkg_name)
        if bl.get("blocked"):
            results["blocklist_hits"] += 1
            results["dangerous"] += 1
            results["dangerous_details"].append({
                "package": pkg_name,
                "reason": bl.get("reason", "In blocklist"),
                "source": "blocklist"
            })
            # Report back for community benefit
            report_dangerous_package(pkg_name, "", bl.get("reason", ""), repo)
        else:
            packages_to_ai_scan.append(pkg)

    # STEP 2: Check for yanked packages (PyPI only)
    print(f"[stillrunning] Checking for yanked packages...")
    remaining = []
    for pkg in packages_to_ai_scan:
        if "@" in pkg:  # npm package
            remaining.append(pkg)
            continue

        pkg_name = re.split(r'[>=<\[\]]', pkg)[0].strip()
        version = None
        if "==" in pkg:
            version = pkg.split("==")[1].strip()

        yanked_check = check_pypi_yanked(pkg_name, version)
        if yanked_check.get("yanked"):
            results["yanked"] += 1
            results["dangerous"] += 1
            results["dangerous_details"].append({
                "package": f"{pkg_name}=={yanked_check.get('version', version)}",
                "reason": "Package was yanked from PyPI",
                "source": "pypi"
            })
        elif not yanked_check.get("exists") and not yanked_check.get("error"):
            results["suspicious"] += 1
        else:
            remaining.append(pkg)
            results["clean"] += 1

    # STEP 3: AI scan for remaining (if token provided)
    if token and remaining:
        print(f"[stillrunning] AI scanning {len(remaining)} packages...")
        api_result = call_api(remaining, token, repo, imports if scan_imports else [])
        if "error" not in api_result:
            summary = api_result.get("summary", {})
            results["suspicious"] += summary.get("suspicious", 0)
            dangerous_from_ai = summary.get("dangerous", 0)
            results["dangerous"] += dangerous_from_ai
            results["clean"] += summary.get("clean", 0) - results["clean"]

            # Add dangerous details from AI
            for pkg_result in api_result.get("packages", []):
                if pkg_result.get("status") == "DANGEROUS":
                    results["dangerous_details"].append({
                        "package": pkg_result.get("name"),
                        "score": pkg_result.get("score"),
                        "reason": pkg_result.get("reason", "AI flagged as dangerous"),
                        "source": "ai"
                    })
                    # Report to community
                    report_dangerous_package(
                        pkg_result.get("name"),
                        pkg_result.get("version", ""),
                        pkg_result.get("reason", ""),
                        repo
                    )
    else:
        results["clean"] += len(remaining)

    # Print summary
    print_summary(results, len(packages), len(imports))

    # Set outputs
    set_output("dangerous-count", str(results["dangerous"]))
    set_output("suspicious-count", str(results["suspicious"]))
    set_output("blocklist-hits", str(results["blocklist_hits"]))
    set_output("yanked-count", str(results["yanked"]))
    set_output("imports-scanned", str(len(imports)))
    set_output("packages-scanned", str(len(packages)))

    # Post PR comment if issues found
    if comment_pr and (results["dangerous"] > 0 or results["suspicious"] > 0):
        comment = f"## stillrunning Security Scan\n\n"
        comment += f"Scanned **{len(packages)}** packages"
        if imports:
            comment += f" + **{len(imports)}** imports"
        comment += f"\n\n"

        if results["dangerous"] > 0:
            comment += "### Dangerous Packages Found\n\n"
            comment += "| Package | Reason |\n|---------|--------|\n"
            for d in results["dangerous_details"]:
                comment += f"| `{d['package']}` | {d.get('reason', 'Known malicious')} |\n"
            comment += "\n"

        comment += f"**Summary:** {results['clean']} clean, {results['suspicious']} suspicious, {results['dangerous']} dangerous\n"
        post_pr_comment(comment)

    # Determine exit
    if results["dangerous"] > 0 and fail_dangerous:
        set_output("result", "fail")
        return 1
    elif results["suspicious"] > 0 and fail_suspicious:
        set_output("result", "fail")
        return 1
    else:
        set_output("result", "pass")
        return 0


if __name__ == "__main__":
    sys.exit(main())
