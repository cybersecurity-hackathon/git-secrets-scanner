"""SENSOR: Git repository traversal and content collection.

The Collector is the first stage of the Sensor → Analyser → Responder pipeline.
It opens a Git repository (local or cloned), then extracts content from three
dimensions:

1. **Working tree** — all currently tracked files (HEAD content).
2. **Commit history** — diffs from every commit on every branch, which catches
   secrets that were committed and later deleted.
3. **Staged changes** — files in the Git index (pre-commit hook use case).

Each unit of extractable content is wrapped in a ``ScanTarget`` dataclass and
yielded as a generator to keep memory usage constant even on large repos.

Usage::

    from scanner.collector import Collector

    collector = Collector("./vulnerable_repo")
    for target in collector.collect():
        # hand to detector
        findings = detector.scan(target)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional, Set

from git import Repo, InvalidGitRepositoryError, NoSuchPathError
from git.objects.commit import Commit

from .models import ScanSource, ScanTarget

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File-type filtering
# ---------------------------------------------------------------------------

# Binary / non-text extensions we skip to avoid false positives and save time.
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".sqlite", ".db",
    ".DS_Store",
}

# Maximum file size (in bytes) we'll scan.  Anything larger is likely a
# data file or vendored dependency — not worth the CPU.
MAX_FILE_SIZE_BYTES: int = 1_048_576  # 1 MB


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class Collector:
    """Git repository content collector (Sensor stage).

    Parameters
    ----------
    repo_path : str | Path
        Path to a local Git repository (must contain ``.git/``).
    scan_history : bool
        Whether to traverse full commit history across all branches.
    scan_staged : bool
        Whether to scan staged (index) changes.
    max_commits : int | None
        Cap on the number of commits to traverse (newest first).
        ``None`` means unlimited.

    Raises
    ------
    ValueError
        If ``repo_path`` is not a valid Git repository.
    """

    def __init__(
        self,
        repo_path: str | Path,
        scan_history: bool = True,
        scan_staged: bool = False,
        max_commits: Optional[int] = None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.scan_history = scan_history
        self.scan_staged = scan_staged
        self.max_commits = max_commits

        try:
            self.repo = Repo(str(self.repo_path))
        except (InvalidGitRepositoryError, NoSuchPathError) as exc:
            raise ValueError(
                f"'{self.repo_path}' is not a valid Git repository: {exc}"
            ) from exc

        if self.repo.bare:
            raise ValueError(
                f"'{self.repo_path}' is a bare repository — "
                "working-tree scanning is not possible."
            )

        # Statistics (populated during collection)
        self.stats = {
            "files_scanned": 0,
            "commits_scanned": 0,
            "branches_scanned": 0,
            "skipped_binary": 0,
            "skipped_too_large": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self) -> Generator[ScanTarget, None, None]:
        """Yield ``ScanTarget`` objects from all configured scan dimensions.

        This is the main entry point.  The detector should iterate over
        the returned generator::

            for target in collector.collect():
                findings = detector.scan(target)
        """
        logger.info("Starting collection from: %s", self.repo_path)

        # 1. Working tree (current HEAD)
        yield from self._collect_working_tree()

        # 2. Full commit history (if enabled)
        if self.scan_history:
            yield from self._collect_history()

        # 3. Staged changes (if enabled)
        if self.scan_staged:
            yield from self._collect_staged()

        logger.info(
            "Collection complete — %d files, %d commits, %d branches",
            self.stats["files_scanned"],
            self.stats["commits_scanned"],
            self.stats["branches_scanned"],
        )

    # ------------------------------------------------------------------
    # Private: Working-tree scan
    # ------------------------------------------------------------------

    def _collect_working_tree(self) -> Generator[ScanTarget, None, None]:
        """Yield ``ScanTarget`` for every tracked file at HEAD."""
        logger.debug("Scanning working tree …")

        # Determine the active branch name
        try:
            branch_name = str(self.repo.active_branch)
        except TypeError:
            branch_name = "HEAD"  # detached HEAD

        head_commit = self.repo.head.commit

        for item in head_commit.tree.traverse():
            # Only process blobs (files), not trees (directories)
            if item.type != "blob":
                continue

            rel_path = item.path

            if self._should_skip(rel_path, item.size):
                continue

            try:
                content = item.data_stream.read().decode("utf-8", errors="replace")
            except Exception as exc:
                logger.warning("Could not read %s: %s", rel_path, exc)
                continue

            self.stats["files_scanned"] += 1

            yield ScanTarget(
                file_path=rel_path,
                content=content,
                commit_sha=str(head_commit.hexsha),
                commit_date=_commit_datetime(head_commit),
                author=str(head_commit.author),
                branch=branch_name,
                source=ScanSource.WORKING_TREE,
            )

    # ------------------------------------------------------------------
    # Private: History scan (all branches, all commits)
    # ------------------------------------------------------------------

    def _collect_history(self) -> Generator[ScanTarget, None, None]:
        """Yield ``ScanTarget`` for diffs in every commit, across all branches."""
        logger.debug("Scanning commit history …")

        seen_commits: Set[str] = set()
        commit_count = 0

        # Iterate over all branches (local + remote tracking)
        branches = list(self.repo.branches)
        self.stats["branches_scanned"] = len(branches)

        for branch in branches:
            branch_name = str(branch)
            logger.debug("  Branch: %s", branch_name)

            try:
                commits = list(branch.commit.iter_parents())
                # Prepend the tip commit itself
                commits = [branch.commit] + commits
            except Exception as exc:
                logger.warning("Could not iterate branch '%s': %s", branch_name, exc)
                continue

            for commit in commits:
                sha = str(commit.hexsha)

                # Dedup across branches (same commit on multiple branches)
                if sha in seen_commits:
                    continue
                seen_commits.add(sha)

                # Honour the commit cap
                if self.max_commits is not None and commit_count >= self.max_commits:
                    logger.debug("Reached max_commits (%d), stopping.", self.max_commits)
                    return

                self.stats["commits_scanned"] += 1
                commit_count += 1

                # Extract diffs from this commit
                yield from self._extract_commit_diffs(commit, branch_name)

    def _extract_commit_diffs(
        self, commit: Commit, branch_name: str
    ) -> Generator[ScanTarget, None, None]:
        """Extract changed-file content from a single commit.

        For the initial commit (no parents), we scan the full tree.
        For subsequent commits, we diff against the first parent.
        """
        try:
            if not commit.parents:
                # Initial commit — scan the full tree snapshot
                for blob in commit.tree.traverse():
                    if blob.type != "blob":
                        continue
                    if self._should_skip(blob.path, blob.size):
                        continue
                    try:
                        content = blob.data_stream.read().decode("utf-8", errors="replace")
                    except Exception:
                        continue

                    yield ScanTarget(
                        file_path=blob.path,
                        content=content,
                        commit_sha=str(commit.hexsha),
                        commit_date=_commit_datetime(commit),
                        author=str(commit.author),
                        branch=branch_name,
                        source=ScanSource.HISTORY,
                    )
            else:
                # Diff against first parent
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)

                for diff in diffs:
                    # Get the file path (handles renames)
                    path = diff.b_path or diff.a_path
                    if not path:
                        continue

                    if self._should_skip_by_ext(path):
                        continue

                    # Extract the diff patch text
                    try:
                        diff_text = diff.diff
                        if isinstance(diff_text, bytes):
                            diff_text = diff_text.decode("utf-8", errors="replace")
                    except Exception:
                        continue

                    if not diff_text or not diff_text.strip():
                        continue

                    # Also try to get the full new-file content (b_blob)
                    full_content = ""
                    if diff.b_blob:
                        try:
                            full_content = (
                                diff.b_blob.data_stream.read()
                                .decode("utf-8", errors="replace")
                            )
                        except Exception:
                            pass

                    # Yield the diff AND optionally the full file content
                    # We prefer full content for pattern matching accuracy
                    content_to_scan = full_content if full_content else diff_text

                    yield ScanTarget(
                        file_path=path,
                        content=content_to_scan,
                        commit_sha=str(commit.hexsha),
                        commit_date=_commit_datetime(commit),
                        author=str(commit.author),
                        branch=branch_name,
                        source=ScanSource.HISTORY,
                    )

        except Exception as exc:
            logger.warning(
                "Error processing commit %s: %s", str(commit.hexsha)[:8], exc
            )

    # ------------------------------------------------------------------
    # Private: Staged changes (git index)
    # ------------------------------------------------------------------

    def _collect_staged(self) -> Generator[ScanTarget, None, None]:
        """Yield ``ScanTarget`` for files staged in the Git index."""
        logger.debug("Scanning staged changes …")

        try:
            branch_name = str(self.repo.active_branch)
        except TypeError:
            branch_name = "HEAD"

        # Diff between HEAD and the index (staged but not yet committed)
        try:
            diffs = self.repo.index.diff("HEAD", create_patch=True)
        except Exception:
            # No HEAD yet (brand new repo) — diff the index against empty
            diffs = self.repo.index.diff(None, create_patch=True)

        for diff in diffs:
            path = diff.b_path or diff.a_path
            if not path or self._should_skip_by_ext(path):
                continue

            try:
                diff_text = diff.diff
                if isinstance(diff_text, bytes):
                    diff_text = diff_text.decode("utf-8", errors="replace")
            except Exception:
                continue

            if not diff_text or not diff_text.strip():
                continue

            yield ScanTarget(
                file_path=path,
                content=diff_text,
                commit_sha="STAGED",
                commit_date=datetime.now(timezone.utc),
                author="(staged)",
                branch=branch_name,
                source=ScanSource.STAGED,
            )

    # ------------------------------------------------------------------
    # Private: Filtering helpers
    # ------------------------------------------------------------------

    def _should_skip(self, file_path: str, size: int) -> bool:
        """Return True if this file should be skipped."""
        if self._should_skip_by_ext(file_path):
            self.stats["skipped_binary"] += 1
            return True

        if size > MAX_FILE_SIZE_BYTES:
            logger.debug("Skipping (too large: %d bytes): %s", size, file_path)
            self.stats["skipped_too_large"] += 1
            return True

        return False

    @staticmethod
    def _should_skip_by_ext(file_path: str) -> bool:
        """Return True if the file has a binary/non-text extension."""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in BINARY_EXTENSIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _commit_datetime(commit: Commit) -> datetime:
    """Convert a GitPython Commit's authored_date to a timezone-aware datetime."""
    return datetime.fromtimestamp(commit.authored_date, tz=timezone.utc)
