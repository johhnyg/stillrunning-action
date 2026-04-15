#!/usr/bin/env python3
"""
stillrunning GitHub Action — Scan dependencies for supply chain attacks.
"""
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

API_URL = "https://stillrunning.io/api/github-action/scan"


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
            print(f"[stillrunning] Parsed {pattern}: {len(packages)} packages so far")

    # Deduplicate
    return list(set(packages))


def call_api(packages: list, token: str, repo: str) -> dict:
    """Call stillrunning.io API."""
    payload = json.dumps({
        "packages": packages,
        "repo": repo,
        "token": token
    }).encode()

    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "stillrunning-action/1.0"
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
                "User-Agent": "stillrunning-action/1.0"
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

    fail_dangerous = fail_dangerous.lower() == "true"
    fail_suspicious = fail_suspicious.lower() == "true"
    comment_pr = comment_pr.lower() == "true"

    print("=" * 60)
    print("stillrunning Security Scan")
    print("=" * 60)

    # Parse files
    file_list = [f.strip() for f in files.split(",")]
    packages = find_and_parse_files(file_list)

    if not packages:
        print("[stillrunning] No packages found to scan")
        set_output("result", "pass")
        set_output("dangerous-count", "0")
        set_output("suspicious-count", "0")
        return 0

    print(f"[stillrunning] Scanning {len(packages)} packages...")

    # Get repo name
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")

    # Call API
    result = call_api(packages, token, repo)

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
