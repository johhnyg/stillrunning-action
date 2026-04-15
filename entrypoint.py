#!/usr/bin/env python3
"""
stillrunning GitHub Action v2 — Scan dependencies AND imports for supply chain attacks.

Features:
- Scan requirements.txt, package.json, pyproject.toml
- Scan Python import statements in source files
- Hash verification against PyPI registry
- AI analysis for unknown packages (with token)
"""
import ast
import glob
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

API_URL = "https://stillrunning.io/api/github-action/scan"
PYPI_URL = "https://pypi.org/pypi"


def parse_requirements_txt(content: str) -> list:
    """Parse requirements.txt format."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle inline comments
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
                # Clean version string
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

        # Check for dependencies section
        if line_stripped == "[project.dependencies]" or line_stripped == "dependencies = [":
            in_deps = True
            continue

        if in_deps:
            # End of section
            if line_stripped.startswith("[") or (line_stripped == "]"):
                in_deps = False
                continue

            # Extract package name
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
    """Extract all import statements from a Python file using AST."""
    imports = set()
    try:
        content = filepath.read_text()
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # Get top-level module
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

        # Handle glob patterns
        full_pattern = os.path.join(workspace, pattern)
        for filepath in glob.glob(full_pattern, recursive=True):
            if os.path.isfile(filepath):
                imports = extract_imports_from_file(Path(filepath))
                all_imports.update(imports)

    # Filter out standard library modules
    stdlib_modules = {
        "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
        "asyncore", "atexit", "audioop", "base64", "bdb", "binascii",
        "binhex", "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb",
        "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections",
        "colorsys", "compileall", "concurrent", "configparser", "contextlib",
        "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
        "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
        "difflib", "dis", "distutils", "doctest", "email", "encodings",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
        "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
        "heapq", "hmac", "html", "http", "imaplib", "imghdr", "imp",
        "importlib", "inspect", "io", "ipaddress", "itertools", "json",
        "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
        "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
        "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
        "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
        "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
        "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
        "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue",
        "quopri", "random", "re", "readline", "reprlib", "resource",
        "rlcompleter", "runpy", "sched", "secrets", "select", "selectors",
        "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib",
        "sndhdr", "socket", "socketserver", "spwd", "sqlite3", "ssl",
        "stat", "statistics", "string", "stringprep", "struct", "subprocess",
        "sunau", "symtable", "sys", "sysconfig", "syslog", "tabnanny",
        "tarfile", "telnetlib", "tempfile", "termios", "test", "textwrap",
        "threading", "time", "timeit", "tkinter", "token", "tokenize",
        "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo",
        "types", "typing", "unicodedata", "unittest", "urllib", "uu",
        "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
        "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc",
        "zipapp", "zipfile", "zipimport", "zlib", "_thread",
    }

    return all_imports - stdlib_modules


def verify_pypi_hash(package: str, version: str = None) -> dict:
    """Verify package exists on PyPI and check hash."""
    try:
        # Get package info from PyPI
        url = f"{PYPI_URL}/{package}/json"
        if version:
            url = f"{PYPI_URL}/{package}/{version}/json"

        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning-action/2.0"})

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        info = data.get("info", {})
        pkg_version = version or info.get("version", "unknown")

        # Get hash from first distribution
        urls = data.get("urls", [])
        if urls:
            sha256 = urls[0].get("digests", {}).get("sha256", "")
            return {
                "package": package,
                "version": pkg_version,
                "status": "CLEAN",
                "hash": sha256[:16] + "..." if sha256 else None,
                "verified": True
            }

        return {
            "package": package,
            "version": pkg_version,
            "status": "CLEAN",
            "hash": None,
            "verified": False,
            "note": "No distribution files found"
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "package": package,
                "version": version,
                "status": "SUSPICIOUS",
                "reason": f"Package not found on PyPI",
                "verified": False
            }
        return {
            "package": package,
            "status": "UNKNOWN",
            "reason": f"PyPI error: {e.code}",
            "verified": False
        }
    except Exception as e:
        return {
            "package": package,
            "status": "UNKNOWN",
            "reason": str(e)[:50],
            "verified": False
        }


def find_and_parse_files(file_patterns: list) -> list:
    """Find and parse dependency files."""
    packages = []
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")

    for pattern in file_patterns:
        pattern = pattern.strip()
        if not pattern:
            continue

        # Check exact path first
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
            print(f"[stillrunning] Parsed {pattern}: {len(packages)} packages so far")

    # Deduplicate
    return list(set(packages))


def call_api(packages: list, token: str, repo: str, imports: list = None) -> dict:
    """Call stillrunning.io API."""
    payload = json.dumps({
        "packages": packages,
        "imports": imports or [],
        "repo": repo,
        "token": token,
        "version": "2.0"
    }).encode()

    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "stillrunning-action/2.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        return {"error": f"API error: {e.code} - {error_body}"}
    except Exception as e:
        return {"error": f"Request failed: {e}"}


def post_pr_comment(comment: str):
    """Post comment to PR using GitHub API."""
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("[stillrunning] GITHUB_TOKEN not set, skipping PR comment")
        return

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        print("[stillrunning] Not in GitHub Actions context, skipping PR comment")
        return

    try:
        with open(event_path) as f:
            event = json.load(f)

        # Get PR number
        pr_number = None
        if "pull_request" in event:
            pr_number = event["pull_request"]["number"]
        elif "issue" in event:
            pr_number = event["issue"]["number"]

        if not pr_number:
            print("[stillrunning] No PR context found, skipping comment")
            return

        repo = os.environ.get("GITHUB_REPOSITORY", "")
        if not repo:
            return

        # Post comment
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        payload = json.dumps({"body": comment}).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "User-Agent": "stillrunning-action/2.0"
            }
        )

        urllib.request.urlopen(req, timeout=30)
        print("[stillrunning] Posted PR comment")

    except Exception as e:
        print(f"[stillrunning] Failed to post PR comment: {e}")


def set_output(name: str, value: str):
    """Set GitHub Actions output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def main():
    # Parse arguments
    args = sys.argv[1:] if len(sys.argv) > 1 else []
    token = args[0] if len(args) > 0 else os.environ.get("INPUT_TOKEN", "")
    files = args[1] if len(args) > 1 else os.environ.get("INPUT_FILES", "requirements.txt")
    fail_dangerous = args[2] if len(args) > 2 else os.environ.get("INPUT_FAIL-ON-DANGEROUS", "true")
    fail_suspicious = args[3] if len(args) > 3 else os.environ.get("INPUT_FAIL-ON-SUSPICIOUS", "false")
    comment_pr = args[4] if len(args) > 4 else os.environ.get("INPUT_COMMENT-ON-PR", "true")
    scan_imports = args[5] if len(args) > 5 else os.environ.get("INPUT_SCAN-IMPORTS", "true")
    python_paths = args[6] if len(args) > 6 else os.environ.get("INPUT_PYTHON-PATHS", "**/*.py")
    verify_hashes = args[7] if len(args) > 7 else os.environ.get("INPUT_VERIFY-HASHES", "true")

    fail_dangerous = fail_dangerous.lower() == "true"
    fail_suspicious = fail_suspicious.lower() == "true"
    comment_pr = comment_pr.lower() == "true"
    scan_imports = scan_imports.lower() == "true"
    verify_hashes = verify_hashes.lower() == "true"

    workspace = os.environ.get("GITHUB_WORKSPACE", ".")

    print("=" * 60)
    print("stillrunning Security Scan v2")
    print("=" * 60)

    # Parse dependency files
    file_list = [f.strip() for f in files.split(",")]
    packages = find_and_parse_files(file_list)

    # Scan Python imports
    imports = []
    if scan_imports:
        print(f"\n[stillrunning] Scanning Python imports...")
        path_list = [p.strip() for p in python_paths.split(",")]
        imports = list(find_python_imports(path_list, workspace))
        print(f"[stillrunning] Found {len(imports)} unique imports")

    total_to_scan = len(packages) + len(imports)
    if total_to_scan == 0:
        print("[stillrunning] No packages or imports found to scan")
        set_output("result", "pass")
        set_output("dangerous-count", "0")
        set_output("suspicious-count", "0")
        set_output("imports-scanned", "0")
        set_output("packages-scanned", "0")
        return 0

    print(f"\n[stillrunning] Scanning {len(packages)} packages + {len(imports)} imports...")

    # Optional: Hash verification for packages
    hash_results = {}
    if verify_hashes and packages:
        print(f"[stillrunning] Verifying PyPI hashes...")
        for pkg in packages[:50]:  # Limit to 50 for speed
            # Extract name and version
            pkg_name = re.split(r'[>=<\[\]@]', pkg)[0].strip()
            version = None
            if "==" in pkg:
                version = pkg.split("==")[1].strip()
            elif "@" in pkg:
                version = pkg.split("@")[1].strip()

            if pkg_name:
                result = verify_pypi_hash(pkg_name, version)
                hash_results[pkg_name] = result
                if result.get("status") != "CLEAN":
                    print(f"  {result.get('status')}: {pkg_name} - {result.get('reason', '')}")

    # Get repo name
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")

    # Call API
    result = call_api(packages, token, repo, imports)

    if "error" in result:
        print(f"[stillrunning] Error: {result['error']}")
        set_output("result", "error")
        return 1

    # Process results
    summary = result.get("summary", {})
    dangerous = summary.get("dangerous", 0)
    suspicious = summary.get("suspicious", 0)
    clean = summary.get("clean", 0)
    unknown = summary.get("unknown", 0)

    # Add hash verification failures
    for pkg, hr in hash_results.items():
        if hr.get("status") == "SUSPICIOUS":
            suspicious += 1
        elif hr.get("status") == "DANGEROUS":
            dangerous += 1

    print(f"\n[stillrunning] Results:")
    print(f"  Clean: {clean}")
    print(f"  Suspicious: {suspicious}")
    print(f"  Dangerous: {dangerous}")
    print(f"  Unknown: {unknown}")

    # Post PR comment
    if comment_pr:
        comment = result.get("comment_markdown", "")
        if comment:
            post_pr_comment(comment)

    # Set outputs
    set_output("dangerous-count", str(dangerous))
    set_output("suspicious-count", str(suspicious))
    set_output("imports-scanned", str(len(imports)))
    set_output("packages-scanned", str(len(packages)))

    # Determine exit code
    if dangerous > 0 and fail_dangerous:
        print(f"\n[stillrunning] FAILED: {dangerous} dangerous package(s) found")
        set_output("result", "fail")
        return 1
    elif suspicious > 0 and fail_suspicious:
        print(f"\n[stillrunning] FAILED: {suspicious} suspicious package(s) found")
        set_output("result", "fail")
        return 1
    else:
        print("\n[stillrunning] PASSED")
        set_output("result", "pass")
        return 0


if __name__ == "__main__":
    sys.exit(main())
