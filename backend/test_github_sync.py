import hashlib
import hmac
import unittest

from github_sync import (
    answer_latest_commit_question,
    is_latest_commit_question,
    normalize_commit,
    normalize_repository,
    push_payload_commits,
    verify_webhook_signature,
)


class GitHubSyncTests(unittest.TestCase):
    def test_normalizes_repository_name(self):
        self.assertEqual(normalize_repository("apache/axis-axis2-java-core"), "apache/axis-axis2-java-core")

    def test_rejects_invalid_repository_name(self):
        with self.assertRaises(ValueError):
            normalize_repository("https://github.com/apache/axis-axis2-java-core")

    def test_verifies_github_signature(self):
        body = b'{"ref":"refs/heads/main"}'
        secret = "local-test-secret"
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        self.assertTrue(verify_webhook_signature(body, f"sha256={digest}", secret))
        self.assertFalse(verify_webhook_signature(body, f"sha256={digest}", "wrong-secret"))
        self.assertFalse(verify_webhook_signature(body, digest, secret))

    def test_normalizes_push_commit_and_file_changes(self):
        payload = {
            "repository":{"full_name":"apache/axis-axis2-java-core"},
            "commits":[{
                "id":"abc123",
                "message":"Fix Axis2 client",
                "timestamp":"2026-11-17T10:00:00Z",
                "author":{"name":"Developer"},
                "added":["src/New.java"],
                "removed":[],
                "modified":["src/Client.java"],
            }],
        }

        commits = push_payload_commits(payload, "apache/axis-axis2-java-core")

        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0]["sha"], "abc123")
        self.assertEqual(commits[0]["author"], "Developer")
        self.assertEqual(
            [file["filename"] for file in commits[0]["files"]],
            ["src/New.java", "src/Client.java"],
        )

    def test_rejects_push_from_another_repository(self):
        payload = {"repository":{"full_name":"someone/else"}, "commits":[]}

        with self.assertRaises(ValueError):
            push_payload_commits(payload, "apache/axis-axis2-java-core")

    def test_ignores_commit_without_timestamp(self):
        self.assertIsNone(normalize_commit({"sha":"abc123"}, "apache/axis-axis2-java-core"))

    def test_normalizes_commit_timestamps_to_utc(self):
        commit = {
            "sha":"abc123",
            "commit":{
                "author":{"date":"2026-11-17T12:00:00+02:00"},
                "message":"Fix Axis2 client",
            },
        }

        normalized = normalize_commit(commit, "apache/axis-axis2-java-core")

        self.assertEqual(normalized["date"], "2026-11-17T10:00:00Z")

    def test_ignores_commit_with_invalid_timestamp(self):
        self.assertIsNone(normalize_commit({
            "sha":"abc123",
            "commit":{"author":{"date":"not-a-date"}},
        }, "apache/axis-axis2-java-core"))

    def test_latest_commit_question_returns_commit_evidence(self):
        commits = [{
            "commit_hash":"abc123",
            "repository":"apache/axis-axis2-java-core",
            "message":"Fix Axis2 client",
            "author":"Developer",
            "date":"2026-11-17T10:00:00Z",
            "commit_url":"https://github.com/apache/axis-axis2-java-core/commit/abc123",
            "files_changed":[{"filename":"src/Client.java"}],
        }]

        answer = answer_latest_commit_question(
            "What is the latest GitHub commit?",
            commits,
            "apache/axis-axis2-java-core",
        )

        self.assertEqual(answer["mode"], "github_commit_lookup")
        self.assertIn("Fix Axis2 client", answer["answer"])
        self.assertIn("[commit:abc123]", answer["answer"])
        self.assertEqual(answer["evidence"][0]["files_changed"][0]["filename"], "src/Client.java")

    def test_latest_commit_question_reports_no_ingested_commits(self):
        answer = answer_latest_commit_question(
            "Show the latest commit",
            [],
            "apache/axis-axis2-java-core",
        )

        self.assertIn("No GitHub commits have been ingested", answer["answer"])
        self.assertEqual(answer["evidence"], [])

    def test_non_latest_commit_question_uses_normal_retrieval(self):
        self.assertIsNone(answer_latest_commit_question(
            "Explain commits mentioning the HTTP client",
            [],
            "apache/axis-axis2-java-core",
        ))
        self.assertFalse(is_latest_commit_question("Explain commits mentioning the HTTP client"))
        self.assertTrue(is_latest_commit_question("Show me the most recent commit"))


if __name__ == "__main__":
    unittest.main()
