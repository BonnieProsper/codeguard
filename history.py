"""
Git history scanning for CodeGuard.

This module scans git commit history for secrets that may have been committed
in the past. Uses parallel processing for performance and generates detailed
reports showing which commits contain secrets.

Key features:
- Parallel commit processing (4 workers by default)
- Progress reporting for long-running scans
- Detailed remediation suggestions (BFG, git-filter-repo)
- Smart caching to avoid re-scanning same content
- Configurable depth (scan last N commits or all history)
"""

import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class CommitFinding:
    """
    Represents a secret found in a specific commit.
    
    Tracks not just what was found, but where and when, to help with
    remediation decisions.
    """
    
    __slots__ = (
        'commit_hash', 'author', 'date', 'message', 'filepath',
        'secret_type', 'line_number', 'matched_value', 'severity'
    )
    
    def __init__(
        self,
        commit_hash: str,
        author: str,
        date: str,
        message: str,
        filepath: str,
        secret_type: str,
        line_number: int,
        matched_value: str,
        severity: str
    ):
        self.commit_hash = commit_hash
        self.author = author
        self.date = date
        self.message = message
        self.filepath = filepath
        self.secret_type = secret_type
        self.line_number = line_number
        self.matched_value = matched_value
        self.severity = severity


class HistoryScanner:
    """
    Scans git commit history for secrets with performance optimizations.
    
    Uses parallel processing to scan multiple commits simultaneously and
    caches file content by hash to avoid duplicate scans.
    """
    
    def __init__(self, detector, max_workers: int = 4):
        """
        Initialize history scanner.
        
        Args:
            detector: SecretDetector instance for pattern matching
            max_workers: Number of parallel workers (default 4)
        """
        self.detector = detector
        self.max_workers = max_workers
        self._scanned_hashes: Set[str] = set()  # Cache to avoid re-scanning
    
    def get_commit_list(self, max_commits: Optional[int] = None) -> List[Dict]:
        """
        Get list of commits to scan with metadata.
        
        Args:
            max_commits: Maximum number of commits to scan (None = all)
            
        Returns:
            List of commit metadata dicts
        """
        try:
            # Format: hash|author|date|subject
            cmd = ['git', 'log', '--format=%H|%an|%ai|%s']
            if max_commits:
                cmd.append(f'-{max_commits}')
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|', 3)
                if len(parts) == 4:
                    commits.append({
                        'hash': parts[0],
                        'author': parts[1],
                        'date': parts[2],
                        'message': parts[3]
                    })
            
            return commits
            
        except subprocess.TimeoutExpired:
            print("Warning: Git log timed out, limiting to recent commits")
            return self.get_commit_list(max_commits=100)
        except subprocess.CalledProcessError as e:
            print(f"Error getting git log: {e.stderr}")
            return []
    
    def get_commit_files(self, commit_hash: str) -> List[str]:
        """
        Get list of files modified in a commit.
        
        Args:
            commit_hash: Git commit hash
            
        Returns:
            List of file paths
        """
        try:
            result = subprocess.run(
                ['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', commit_hash],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            
            return [f.strip() for f in result.stdout.split('\n') if f.strip()]
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return []
    
    def get_file_content(self, commit_hash: str, filepath: str) -> Optional[str]:
        """
        Get file content from a specific commit.
        
        Args:
            commit_hash: Git commit hash
            filepath: Path to file in that commit
            
        Returns:
            File content or None if unavailable
        """
        try:
            # Try to get file content from this commit
            result = subprocess.run(
                ['git', 'show', f'{commit_hash}:{filepath}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout
            return None
            
        except (subprocess.TimeoutExpired, UnicodeDecodeError):
            # File is binary or timed out
            return None
    
    def scan_commit(self, commit_meta: Dict) -> List[CommitFinding]:
        """
        Scan a single commit for secrets.
        
        Args:
            commit_meta: Commit metadata dict
            
        Returns:
            List of findings in this commit
        """
        findings = []
        commit_hash = commit_meta['hash']
        
        # Get files modified in this commit
        files = self.get_commit_files(commit_hash)
        
        for filepath in files:
            # Skip binary and large files by extension
            file_ext = Path(filepath).suffix.lower()
            if file_ext in {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.exe', '.bin'}:
                continue
            
            content = self.get_file_content(commit_hash, filepath)
            if not content:
                continue
            
            # Check if we've already scanned this exact content
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            if content_hash in self._scanned_hashes:
                continue
            
            self._scanned_hashes.add(content_hash)
            
            # Scan for secrets
            detections = self.detector.scan_content(content, filepath)
            
            for detection in detections:
                findings.append(CommitFinding(
                    commit_hash=commit_hash,
                    author=commit_meta['author'],
                    date=commit_meta['date'],
                    message=commit_meta['message'],
                    filepath=filepath,
                    secret_type=detection['pattern_name'],
                    line_number=detection['line_number'],
                    matched_value=detection['matched_value'],
                    severity=detection['severity']
                ))
        
        return findings
    
    def scan_history(
        self, 
        max_commits: Optional[int] = None,
        progress_callback = None
    ) -> List[CommitFinding]:
        """
        Scan git history for secrets with parallel processing.
        
        Args:
            max_commits: Maximum commits to scan (None = all history)
            progress_callback: Optional function(current, total) for progress
            
        Returns:
            List of all findings across history
        """
        commits = self.get_commit_list(max_commits)
        
        if not commits:
            return []
        
        all_findings = []
        total = len(commits)
        
        # Parallel processing for performance
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all commit scans
            future_to_commit = {
                executor.submit(self.scan_commit, commit): commit 
                for commit in commits
            }
            
            # Process results as they complete
            for i, future in enumerate(as_completed(future_to_commit), 1):
                if progress_callback:
                    progress_callback(i, total)
                
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    # Log error but continue scanning
                    commit = future_to_commit[future]
                    print(f"Error scanning commit {commit['hash'][:8]}: {e}")
        
        return all_findings
    
    @staticmethod
    def generate_report(findings: List[CommitFinding]) -> str:
        """
        Generate human-readable report from findings.
        
        Args:
            findings: List of CommitFinding objects
            
        Returns:
            Formatted report string
        """
        if not findings:
            return "✅ No secrets found in git history!"
        
        # Group by severity
        critical = [f for f in findings if f.severity == 'critical']
        high = [f for f in findings if f.severity == 'high']
        medium = [f for f in findings if f.severity == 'medium']
        
        # Build report
        lines = [
            "🔍 Git History Scan Report",
            "=" * 70,
            f"Scanned commits: {len(set(f.commit_hash for f in findings))}",
            f"Total secrets found: {len(findings)}",
            f"  Critical: {len(critical)}",
            f"  High: {len(high)}",
            f"  Medium: {len(medium)}",
            "",
        ]
        
        if critical:
            lines.extend([
                "🚨 CRITICAL ISSUES",
                "-" * 70,
            ])
            for finding in critical[:10]:  # Show first 10
                lines.extend([
                    f"Commit: {finding.commit_hash[:8]}",
                    f"Author: {finding.author}",
                    f"Date: {finding.date}",
                    f"File: {finding.filepath}:{finding.line_number}",
                    f"Type: {finding.secret_type}",
                    f"Message: {finding.message}",
                    "",
                ])
            
            if len(critical) > 10:
                lines.append(f"... and {len(critical) - 10} more critical issues")
                lines.append("")
        
        # Remediation advice
        lines.extend([
            "💡 REMEDIATION",
            "-" * 70,
            "To remove secrets from git history, use one of these tools:",
            "",
            "1. BFG Repo-Cleaner (recommended for speed):",
            "   java -jar bfg.jar --delete-files secret_file.txt",
            "   java -jar bfg.jar --replace-text passwords.txt",
            "",
            "2. git-filter-repo (recommended for complex cases):",
            "   git filter-repo --path sensitive.txt --invert-paths",
            "   git filter-repo --replace-text expressions.txt",
            "",
            "3. Manual rewrite (smallest repos only):",
            "   git filter-branch --force --index-filter \\",
            "     'git rm --cached --ignore-unmatch path/to/file' \\",
            "     --prune-empty --tag-name-filter cat -- --all",
            "",
            "⚠️  After cleaning history:",
            "   1. Force push: git push --force --all",
            "   2. Rotate ALL affected secrets",
            "   3. Notify team members to re-clone repository",
            "",
        ])
        
        # Unique commits affected
        unique_commits = set(f.commit_hash for f in findings)
        if len(unique_commits) <= 20:
            lines.extend([
                "📋 Affected commits:",
                ""
            ])
            for commit_hash in sorted(unique_commits):
                lines.append(f"  {commit_hash}")
        else:
            lines.append(f"📋 {len(unique_commits)} commits affected (too many to list)")
        
        return "\n".join(lines)
    
    @staticmethod
    def export_findings_json(findings: List[CommitFinding]) -> str:
        """
        Export findings as JSON for programmatic processing.
        
        Args:
            findings: List of CommitFinding objects
            
        Returns:
            JSON string
        """
        import json
        
        data = {
            'scan_date': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': [
                {
                    'commit': f.commit_hash,
                    'author': f.author,
                    'date': f.date,
                    'file': f.filepath,
                    'line': f.line_number,
                    'type': f.secret_type,
                    'severity': f.severity,
                    'message': f.message
                }
                for f in findings
            ]
        }
        
        return json.dumps(data, indent=2)


def scan_repository_history(
    detector,
    max_commits: Optional[int] = None,
    max_workers: int = 4,
    show_progress: bool = True
) -> List[CommitFinding]:
    """
    Convenience function to scan repository history.
    
    Args:
        detector: SecretDetector instance
        max_commits: Maximum commits to scan (None = all)
        max_workers: Number of parallel workers
        show_progress: Whether to show progress indicator
        
    Returns:
        List of findings
    """
    scanner = HistoryScanner(detector, max_workers=max_workers)
    
    if show_progress:
        def progress(current, total):
            pct = (current / total) * 100
            print(f"Scanning commits: {current}/{total} ({pct:.1f}%)", end='\r')
        
        findings = scanner.scan_history(max_commits, progress_callback=progress)
        print()  # New line after progress
    else:
        findings = scanner.scan_history(max_commits)
    
    return findings