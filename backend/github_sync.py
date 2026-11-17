"""GitHub commit polling and webhook validation for ChronoDev."""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Any

import httpx


GITHUB_API = "https://api.github.com"


def normalize_repository(repository: str) -> str:
    parts = repository.strip().strip("/").split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError("GITHUB_REPOSITORY must use the OWNER/REPO format.")
    return "/".join(parts)


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not secret or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def normalize_commit(commit: dict[str, Any], repository: str) -> dict[str, Any] | None:
    """Convert either GitHub REST API or push-webhook commit data to a stable shape."""
    details = commit.get("commit") or {}
    git_author = details.get("author") or {}
    git_committer = details.get("committer") or {}
    actor = commit.get("author") or {}
    sha = str(commit.get("sha") or commit.get("id") or "").strip()
    timestamp = (git_author.get("date") or git_committer.get("date")
                 or commit.get("timestamp") or commit.get("created_at"))
    if not sha or not timestamp:
        return None
    try:
        parsed_timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
    timestamp = parsed_timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    message = str(details.get("message") or commit.get("message") or "").strip()
    files = commit.get("files")
    if not isinstance(files, list):
        files = [
            {"filename":name, "status":status}
            for status, names in (("added", commit.get("added", [])),
                                  ("removed", commit.get("removed", [])),
                                  ("modified", commit.get("modified", [])))
            for name in names if isinstance(name, str)
        ]
    normalized_files = []
    for item in files:
        if isinstance(item, str):
            normalized_files.append({"filename":item})
        elif isinstance(item, dict) and item.get("filename"):
            normalized_files.append({
                key:item[key] for key in ("filename", "status", "additions", "deletions")
                if key in item
            })

    author = str(actor.get("login") or git_author.get("name")
                 or (commit.get("author") or {}).get("name") or "Unknown author")
    url = str(commit.get("html_url") or
              f"https://github.com/{repository}/commit/{sha}")
    return {
        "sha":sha,
        "repository":repository,
        "message":message or "(no commit message)",
        "author":author,
        "date":str(timestamp),
        "url":url,
        "files":normalized_files[:500],
    }


def push_payload_commits(payload: dict[str, Any], expected_repository: str) -> list[dict[str, Any]]:
    repository = str((payload.get("repository") or {}).get("full_name") or "")
    if repository.casefold() != expected_repository.casefold():
        raise ValueError("Webhook repository does not match GITHUB_REPOSITORY.")
    commits = payload.get("commits")
    if not isinstance(commits, list):
        raise ValueError("GitHub push payload does not contain a commits list.")
    return [normalized for item in commits
            if isinstance(item, dict)
            if (normalized := normalize_commit(item, expected_repository))]


def is_latest_commit_question(question: str) -> bool:
    return bool(
        re.search(r"\b(commit|commits)\b", question, re.IGNORECASE)
        and re.search(r"\b(latest|most recent|newest|last|recent)\b", question, re.IGNORECASE)
    )


def answer_latest_commit_question(
    question: str,
    commits: list[dict[str, Any]],
    repository: str,
    max_evidence: int = 5,
) -> dict[str, Any] | None:
    if not is_latest_commit_question(question):
        return None

    plural = bool(re.search(r"\bcommits\b", question, re.IGNORECASE))
    selected = commits[:max_evidence if plural else 1]
    evidence = [{
        "kind":"commit",
        "commit_hash":item.get("commit_hash"),
        "date":item.get("date"),
        "author":item.get("author"),
        "message":item.get("message"),
        "files_changed":item.get("files_changed", []),
        "commit_url":item.get("commit_url"),
        "repository":item.get("repository", repository),
    } for item in selected]

    if not evidence:
        return {
            "answer":f"No GitHub commits have been ingested yet for {repository}. Check the GitHub sync status.",
            "evidence":[],
            "mode":"github_commit_lookup",
        }

    lines = []
    for item in evidence:
        sha = str(item.get("commit_hash") or "")
        message = str(item.get("message") or "(no commit message)")
        citation = f"[commit:{sha}]" if sha else "[commit]"
        lines.append(
            f"- {str(item.get('date') or 'Date not recorded')[:20]} — {message} "
            f"by {item.get('author') or 'Unknown author'} ({citation})"
        )
        files = item.get("files_changed") or []
        if files:
            names = [str(file.get("filename")) for file in files[:8]
                     if isinstance(file, dict) and file.get("filename")]
            if names:
                lines.append(f"  Files changed: {', '.join(names)}")
    title = "Latest GitHub commit" if len(evidence) == 1 else "Latest GitHub commits"
    return {
        "answer":f"{title} for {repository}:\n" + "\n".join(lines),
        "evidence":evidence,
        "mode":"github_commit_lookup",
    }


def poll_github_commits(repository: str, token: str, history, initial_limit: int = 20) -> dict[str, Any]:
    """Fetch new commits since the last ingested SHA and save them idempotently."""
    repository = normalize_repository(repository)
    headers = {
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"ChronoDev-AI",
    }
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"

    with httpx.Client(timeout=30, headers=headers) as client:
        response = client.get(f"{GITHUB_API}/repos/{repository}/commits", params={"per_page":100})
        response.raise_for_status()
        commits = response.json()
        if not isinstance(commits, list):
            raise ValueError("GitHub returned an unexpected commits response.")

        shas = [str(item.get("sha", "")) for item in commits if isinstance(item, dict)]
        known = history.known_github_commits(repository, shas)
        selected = []
        if known:
            for item in commits:
                if not isinstance(item, dict):
                    continue
                if str(item.get("sha", "")) in known:
                    break
                selected.append(item)
        else:
            selected = commits[:max(1, min(initial_limit, 100))]

        normalized_commits = []
        for item in selected:
            sha = str(item.get("sha") or "")
            details_response = client.get(f"{GITHUB_API}/repos/{repository}/commits/{sha}")
            details_response.raise_for_status()
            normalized = normalize_commit(details_response.json(), repository)
            if normalized:
                normalized_commits.append(normalized)

    result = history.ingest_github_commits(repository, normalized_commits)
    return {"repository":repository, "fetched":len(normalized_commits), **result}
