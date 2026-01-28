#!/usr/bin/env python3
"""
CodeGuard - Pre-commit security scanner

Detects hardcoded secrets before they reach your Git repository.
Features 45+ detection patterns, git history scanning, and context-aware
filtering to minimize false positives.

Usage:
    codeguard init              Setup in repository
    codeguard scan              Scan staged files
    codeguard scan-history      Scan git history
    codeguard config            Show configuration
    codeguard uninstall         Remove from repository

Repository: https://github.com/yourusername/codeguard
License: MIT
Version: 1.0.0-beta
"""

import os
import sys
import argparse
import subprocess
import math
import json
from pathlib import Path
from collections import Counter
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Import pattern definitions
try:
    from patterns import ALL_PATTERNS, PATTERN_COUNT, PATTERN_CATEGORIES
    from history import scan_repository_history, HistoryScanner
except ImportError:
    print("Error: patterns.py and history.py must be in the same directory")
    print("Download all files from: https://github.com/yourusername/codeguard")
    sys.exit(1)

# Configuration constants
MINIMUM_ENTROPY_THRESHOLD = 2.5
MINIMUM_SECRET_LENGTH = 12
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    
    @classmethod
    def disable_all(cls):
        """Disable colors for CI/CD environments"""
        for attribute in dir(cls):
            if not attribute.startswith('_') and attribute.isupper():
                setattr(cls, attribute, '')


# Optional Rich library for enhanced output
try:
    from rich.console import Console
    _console = Console()
    USE_RICH = True
except ImportError:
    _console = None
    USE_RICH = False


class SecretDetector:
    """
    Core secret detection engine using patterns from patterns.py.
    
    Provides context-aware filtering to reduce false positives while
    maintaining high detection accuracy for real secrets.
    """
    
    def __init__(self):
        self.patterns = ALL_PATTERNS
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy with character diversity bonus.
        
        Higher entropy indicates randomness typical of generated secrets.
        Character diversity accounts for mixed case, digits, and symbols.
        
        Args:
            text: String to analyze
            
        Returns:
            Entropy value (0-5+, higher = more random)
        """
        if not text or len(text) < 8:
            return 0.0
        
        # Shannon entropy
        counts = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )
        
        # Character diversity bonus (0-1.0)
        has_upper = any(c.isupper() for c in text)
        has_lower = any(c.islower() for c in text)
        has_digit = any(c.isdigit() for c in text)
        has_special = any(not c.isalnum() for c in text)
        
        diversity_bonus = sum([has_upper, has_lower, has_digit, has_special]) * 0.25
        
        return entropy + diversity_bonus
    
    @staticmethod
    def is_test_file(filepath: str) -> bool:
        """
        Identify test/example files using path components.
        
        Uses directory names rather than substring matching to avoid
        false positives like "latest.py" or "contest.py".
        """
        path_parts = Path(filepath).parts
        test_indicators = {
            'test', 'tests', '__tests__', 'spec', 'specs',
            'fixture', 'fixtures', 'mock', 'mocks',
            'example', 'examples', 'sample', 'samples',
            'demo', 'demos', 'docs', 'documentation'
        }
        
        # Check directory names and file suffixes
        return any(
            part.lower() in test_indicators or
            part.lower().endswith(('.test.py', '.spec.py', '_test.py', '_spec.py',
                                 '.test.js', '.spec.js', '_test.js', '_spec.js'))
            for part in path_parts
        )
    
    @staticmethod
    def is_placeholder(value: str) -> bool:
        """Check if value appears to be a placeholder string"""
        placeholders = {
            'your_key_here', 'your_secret_here', 'your_token_here',
            'your-api-key', 'your-secret', 'insert-key-here',
            'example', 'placeholder', 'replace_me', 'changeme',
            'xxx', '***', 'yyy', 'zzz', 'todo', 'fixme',
            '12345', '123456', 'abcdef', 'test', 'demo', 'sample',
            'fake', 'mock', 'dummy', 'foobar'
        }
        value_lower = value.lower()
        return any(placeholder in value_lower for placeholder in placeholders)
    
    @staticmethod
    def is_in_comment(line: str) -> bool:
        """Check if line is a comment"""
        stripped = line.strip()
        comment_starts = ('#', '//', '/*', '*', '--', '<!--')
        return any(stripped.startswith(start) for start in comment_starts)
    
    @staticmethod
    def has_inline_ignore(line: str) -> bool:
        """Check for inline ignore directive"""
        ignore_markers = ('codeguard:ignore', 'codeguard: ignore', 'nosec', 'noqa')
        return any(marker in line.lower() for marker in ignore_markers)
    
    def should_report_secret(
        self,
        value: str,
        filepath: str,
        line: str,
        confidence: int
    ) -> bool:
        """
        Context-aware filtering to minimize false positives.
        
        High-confidence patterns (95+) are always reported because they're
        highly specific (e.g., AWS keys with exact format). Lower confidence
        patterns receive additional scrutiny.
        
        Args:
            value: The matched secret value
            filepath: Path to file containing match
            line: Full line of code containing match
            confidence: Pattern confidence score (0-100)
            
        Returns:
            True if this should be reported as a secret
        """
        # Inline ignore always wins (user override)
        if self.has_inline_ignore(line):
            return False
        
        # Placeholders are never real secrets
        if self.is_placeholder(value):
            return False
        
        # High-confidence patterns always report (even in test files)
        # Real AWS keys in test files are still dangerous
        if confidence >= 95:
            return True
        
        # Medium confidence gets filtered by context
        if self.is_test_file(filepath):
            return False
        
        if self.is_in_comment(line):
            return False
        
        # Check entropy for medium-confidence patterns
        entropy = self.calculate_entropy(value)
        if entropy < MINIMUM_ENTROPY_THRESHOLD:
            return False
        
        # Length check
        if len(value) < MINIMUM_SECRET_LENGTH:
            return False
        
        return True
    
    def scan_content(self, content: str, filepath: str) -> List[Dict]:
        """
        Scan file content for secrets using all patterns.
        
        Args:
            content: File content to scan
            filepath: Path for context
            
        Returns:
            List of finding dictionaries with metadata
        """
        findings = []
        lines = content.split('\n')
        
        for pattern_obj in self.patterns:
            matches = pattern_obj.find_matches(content)
            
            for line_number, matched_value in matches:
                line_content = lines[line_number - 1] if line_number <= len(lines) else ''
                
                # Apply context-aware filtering
                if not self.should_report_secret(
                    matched_value,
                    filepath,
                    line_content,
                    pattern_obj.confidence
                ):
                    continue
                
                # Get context (3 lines before and after)
                context_start = max(0, line_number - 4)
                context_end = min(len(lines), line_number + 3)
                context_lines = lines[context_start:context_end]
                
                findings.append({
                    'pattern_name': pattern_obj.name,
                    'severity': pattern_obj.severity,
                    'confidence': pattern_obj.confidence,
                    'filepath': filepath,
                    'line_number': line_number,
                    'matched_value': matched_value,
                    'line_content': line_content,
                    'context_lines': context_lines,
                    'context_start_line': context_start + 1,
                    'remediation': pattern_obj.remediation,
                    'entropy': self.calculate_entropy(matched_value),
                })
        
        return findings


class GitHelper:
    """Git operations with proper error handling"""
    
    @staticmethod
    def find_git_root() -> Optional[Path]:
        """
        Find git repository root by walking up directory tree.
        
        This allows CodeGuard to work from any subdirectory,
        matching git's own behavior.
        
        Returns:
            Path to git root, or None if not in a repository
        """
        current = Path.cwd().resolve()  # Resolve symlinks
        
        while True:
            if (current / '.git').exists():
                return current
            if current == current.parent:  # At filesystem root
                return None
            current = current.parent
    
    @staticmethod
    def is_git_repo() -> bool:
        """Check if we're inside a git repository"""
        return GitHelper.find_git_root() is not None
    
    @staticmethod
    def get_staged_files() -> List[str]:
        """
        Get list of staged files with proper error handling.
        
        Returns:
            List of relative file paths
        """
        try:
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            return [f.strip() for f in result.stdout.split('\n') if f.strip()]
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}Git operation timed out{Colors.RESET}")
            return []
        except subprocess.CalledProcessError as error:
            if error.stderr:
                print(f"{Colors.RED}Git error: {error.stderr.strip()}{Colors.RESET}")
            return []
        except FileNotFoundError:
            print(f"{Colors.RED}Git not found. Is it installed?{Colors.RESET}")
            return []
    
    @staticmethod
    def get_staged_content(filepath: str) -> Optional[str]:
        """
        Get staged content of a file.
        
        Args:
            filepath: Relative path to file
            
        Returns:
            File content or None if unavailable
        """
        try:
            result = subprocess.run(
                ['git', 'show', f':{filepath}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout if result.returncode == 0 else None
            
        except (subprocess.TimeoutExpired, UnicodeDecodeError):
            return None


class FileScanner:
    """
    File scanning with safety checks and performance optimizations.
    
    Checks file size before reading, detects binary files efficiently,
    and handles encoding errors gracefully.
    """
    
    def __init__(self, detector: SecretDetector):
        self.detector = detector
    
    @staticmethod
    def is_binary(filepath: str) -> bool:
        """
        Detect binary files by checking for null bytes in first 8KB.
        
        Handles UTF-16 text files correctly by checking for BOM markers.
        """
        try:
            with open(filepath, 'rb') as file:
                chunk = file.read(8192)
                
                # Check for UTF-16 BOM (text file, not binary)
                if chunk.startswith((b'\xff\xfe', b'\xfe\xff')):
                    return False
                
                return b'\x00' in chunk
                
        except Exception:
            return True
    
    @staticmethod
    def get_file_size(filepath: str) -> int:
        """Get file size in bytes, returns 0 on error"""
        try:
            return Path(filepath).stat().st_size
        except Exception:
            return 0
    
    def should_scan_file(self, filepath: str) -> Tuple[bool, Optional[str]]:
        """
        Determine if file should be scanned.
        
        Checks are ordered by speed (fastest first) to fail fast.
        
        Returns:
            (should_scan, skip_reason)
        """
        path = Path(filepath)
        
        if not path.exists():
            return False, "File does not exist"
        
        size = self.get_file_size(filepath)
        if size == 0:
            return False, "Empty file"
        
        if size > MAX_FILE_SIZE_BYTES:
            size_mb = size / 1024 / 1024
            return False, f"File too large ({size_mb:.1f}MB)"
        
        if self.is_binary(filepath):
            return False, "Binary file"
        
        return True, None
    
    def scan_file(
        self,
        filepath: str,
        content: Optional[str] = None
    ) -> List[Dict]:
        """
        Scan a single file for secrets.
        
        Args:
            filepath: Path to file
            content: Optional pre-loaded content (for staged files)
            
        Returns:
            List of findings
        """
        if content is None:
            should_scan, reason = self.should_scan_file(filepath)
            if not should_scan:
                return []
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
            except Exception:
                return []
        
        return self.detector.scan_content(content, filepath)


class Reporter:
    """Output formatting with Rich fallback"""
    
    @staticmethod
    def print_header():
        """Print scan header"""
        if USE_RICH and _console:
            _console.print("\n[bold cyan]🛡️  CodeGuard Security Scan[/bold cyan]")
            _console.print("━" * 60)
        else:
            print(f"\n{Colors.CYAN}{Colors.BOLD}🛡️  CodeGuard Security Scan{Colors.RESET}")
            print("━" * 60)
    
    @staticmethod
    def print_progress(current: int, total: int):
        """Print scan progress"""
        percent = (current / total * 100) if total > 0 else 0
        if USE_RICH and _console:
            _console.print(f"Scanning: {current}/{total} files ({percent:.0f}%)", end='\r')
        else:
            print(f"Scanning: {current}/{total} files ({percent:.0f}%)", end='\r', flush=True)
    
    @staticmethod
    def clear_progress():
        """Clear progress line"""
        print(" " * 80, end='\r')
    
    @staticmethod
    def print_finding(finding: Dict, show_context: bool = True):
        """Print a single finding"""
        if USE_RICH and _console:
            Reporter._print_finding_rich(finding, show_context)
        else:
            Reporter._print_finding_plain(finding, show_context)
    
    @staticmethod
    def _print_finding_rich(finding: Dict, show_context: bool):
        """Rich-formatted output"""
        if not _console:
            return
        
        _console.print(f"\n[bold]{finding['filepath']}:{finding['line_number']}[/bold]")
        
        if show_context and finding.get('context_lines'):
            start_line = finding['context_start_line']
            for i, line in enumerate(finding['context_lines']):
                line_num = start_line + i
                if line_num == finding['line_number']:
                    _console.print(f"[red]{line_num:4} | {line}[/red]")
                else:
                    _console.print(f"[dim]{line_num:4} | {line}[/dim]")
        
        _console.print()
        
        severity_colors = {'critical': 'red', 'high': 'yellow', 'medium': 'blue'}
        color = severity_colors.get(finding['severity'], 'white')
        
        _console.print(f"[{color}]⚠️  {finding['pattern_name']}[/{color}]")
        _console.print(
            f"[dim]Confidence: {finding['confidence']}% | "
            f"Entropy: {finding['entropy']:.2f}[/dim]"
        )
        _console.print(f"💡 [bold]Fix:[/bold] {finding['remediation']}")
        _console.print()
    
    @staticmethod
    def _print_finding_plain(finding: Dict, show_context: bool):
        """Plain text output"""
        print(f"\n{Colors.BOLD}{finding['filepath']}:{finding['line_number']}{Colors.RESET}")
        
        if show_context and finding.get('context_lines'):
            start_line = finding['context_start_line']
            for i, line in enumerate(finding['context_lines']):
                line_num = start_line + i
                if line_num == finding['line_number']:
                    print(f"{Colors.RED}{line_num:4} | {line}{Colors.RESET}")
                else:
                    print(f"{Colors.DIM}{line_num:4} | {line}{Colors.RESET}")
        
        print()
        
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.YELLOW,
            'medium': Colors.BLUE,
        }
        color = severity_colors.get(finding['severity'], '')
        
        print(f"{color}⚠️  {finding['pattern_name']}{Colors.RESET}")
        print(f"Confidence: {finding['confidence']}% | Entropy: {finding['entropy']:.2f}")
        print(f"💡 Fix: {finding['remediation']}")
        print()
    
    @staticmethod
    def print_summary(findings: List[Dict], blocked: bool):
        """Print scan summary"""
        critical = sum(1 for f in findings if f['severity'] == 'critical')
        high = sum(1 for f in findings if f['severity'] == 'high')
        medium = sum(1 for f in findings if f['severity'] == 'medium')
        
        if USE_RICH and _console:
            if blocked:
                _console.print(f"\n[bold red]❌ COMMIT BLOCKED[/bold red]")
                _console.print(
                    f"Found {len(findings)} secret(s): "
                    f"{critical} critical, {high} high, {medium} medium"
                )
                _console.print("\n[yellow]Fix the issues above before committing.[/yellow]")
                _console.print("[dim]Tip: Add '# codeguard:ignore' to suppress false positives[/dim]")
            else:
                _console.print(f"\n[bold green]✅ No secrets detected[/bold green]")
                _console.print("Safe to commit!")
        else:
            if blocked:
                print(f"\n{Colors.RED}{Colors.BOLD}❌ COMMIT BLOCKED{Colors.RESET}")
                print(
                    f"Found {len(findings)} secret(s): "
                    f"{critical} critical, {high} high, {medium} medium"
                )
                print(f"\n{Colors.YELLOW}Fix the issues above before committing.{Colors.RESET}")
                print(f"{Colors.DIM}Tip: Add '# codeguard:ignore' to suppress false positives{Colors.RESET}")
            else:
                print(f"\n{Colors.GREEN}{Colors.BOLD}✅ No secrets detected{Colors.RESET}")
                print("Safe to commit!")


class ConfigManager:
    """Configuration file management with sensible defaults"""
    
    DEFAULT_CONFIG = {
        'version': 1,
        'rules': {
            'high_confidence': {'enabled': True, 'min_confidence': 95},
            'medium_confidence': {'enabled': True, 'min_confidence': 70},
        },
        'ignore': {
            'paths': [
                'test/**', 'tests/**', 'spec/**',
                'examples/**', '*.test.*', '*.spec.*',
            ],
        },
    }
    
    CONFIG_FILE = '.codeguard.yml'
    
    @classmethod
    def load_config(cls) -> Dict:
        """Load configuration, falling back to defaults"""
        if not Path(cls.CONFIG_FILE).exists():
            return cls.DEFAULT_CONFIG.copy()
        
        try:
            import yaml
            with open(cls.CONFIG_FILE) as file:
                user_config = yaml.safe_load(file) or {}
            
            config = cls.DEFAULT_CONFIG.copy()
            config.update(user_config)
            return config
        except ImportError:
            # PyYAML not installed, use defaults
            return cls.DEFAULT_CONFIG.copy()
        except Exception as error:
            print(f"{Colors.YELLOW}Warning: Error reading config: {error}{Colors.RESET}")
            return cls.DEFAULT_CONFIG.copy()
    
    @classmethod
    def create_default_config(cls):
        """Create default configuration file"""
        config_content = f"""# CodeGuard Configuration
# https://github.com/yourusername/codeguard

version: 1

# Detection rules
rules:
  high_confidence:
    enabled: true
    min_confidence: 95
  
  medium_confidence:
    enabled: true
    min_confidence: 70

# Files/paths to ignore
ignore:
  paths:
    - test/**
    - tests/**
    - examples/**
    - "*.test.*"
    - "*.spec.*"

# Tip: Add '# codeguard:ignore' to any line to suppress detection
# Patterns: {PATTERN_COUNT} total across {len(PATTERN_CATEGORIES)} categories
"""
        
        with open(cls.CONFIG_FILE, 'w') as file:
            file.write(config_content)


class HookManager:
    """Git hook installation and management"""
    
    HOOK_PATH = Path('.git/hooks/pre-commit')
    HOOK_CONTENT = '''#!/bin/sh
# CodeGuard pre-commit hook
# https://github.com/yourusername/codeguard

# Get repository root
HOOK_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$HOOK_DIR" || exit 1

# Run CodeGuard (handle both local and global installations)
if command -v codeguard >/dev/null 2>&1; then
    codeguard scan --hook
elif [ -f "codeguard.py" ]; then
    python3 codeguard.py scan --hook
else
    echo "Error: codeguard not found"
    exit 1
fi

exit $?
'''
    
    @classmethod
    def install_hook(cls) -> bool:
        """Install pre-commit hook with backup of existing hooks"""
        hook_path = cls.HOOK_PATH
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Backup existing hook
        if hook_path.exists():
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup = hook_path.parent / f"pre-commit.backup.{timestamp}"
            try:
                hook_path.rename(backup)
                print(f"Backed up existing hook: {backup.name}")
            except Exception as error:
                print(f"{Colors.RED}Failed to backup hook: {error}{Colors.RESET}")
                return False
        
        # Install new hook
        try:
            hook_path.write_text(cls.HOOK_CONTENT)
            hook_path.chmod(0o755)
            return True
        except Exception as error:
            print(f"{Colors.RED}Failed to install hook: {error}{Colors.RESET}")
            return False
    
    @classmethod
    def uninstall_hook(cls) -> bool:
        """Uninstall hook and restore backup"""
        hook_path = cls.HOOK_PATH
        
        if not hook_path.exists():
            return True
        
        try:
            content = hook_path.read_text()
            if 'CodeGuard' not in content:
                print(f"{Colors.YELLOW}Hook exists but isn't CodeGuard's{Colors.RESET}")
                return False
            
            hook_path.unlink()
            
            # Restore latest backup
            backups = sorted(hook_path.parent.glob("pre-commit.backup.*"))
            if backups:
                backups[-1].rename(hook_path)
                print(f"Restored: {backups[-1].name}")
            
            return True
        except Exception as error:
            print(f"{Colors.RED}Failed to uninstall: {error}{Colors.RESET}")
            return False


class CLI:
    """Command-line interface"""
    
    @staticmethod
    def cmd_init(args):
        """Initialize CodeGuard in repository"""
        git_root = GitHelper.find_git_root()
        
        if not git_root:
            print(f"{Colors.RED}❌ Not a git repository{Colors.RESET}")
            print(f"\nSearched from: {Path.cwd()}")
            print("Initialize git first: git init")
            return 1
        
        # Move to git root if needed
        if Path.cwd() != git_root:
            print(f"Git repository: {git_root}")
            os.chdir(git_root)
        
        print(f"{Colors.CYAN}{Colors.BOLD}🛡️  CodeGuard Setup{Colors.RESET}")
        print("━" * 60)
        
        # Create config
        ConfigManager.create_default_config()
        print("✓ Created .codeguard.yml")
        
        # Show pattern stats
        print(f"✓ Loaded {PATTERN_COUNT} detection patterns")
        
        # Install hook
        if not HookManager.install_hook():
            print(f"{Colors.RED}✗ Hook installation failed{Colors.RESET}")
            return 1
        
        print("✓ Installed pre-commit hook")
        
        print(f"\n{Colors.GREEN}🎉 Setup complete!{Colors.RESET}")
        print("\nCodeGuard will scan every commit automatically.")
        print(f"\n{Colors.BOLD}Test it:{Colors.RESET} git add . && git commit -m 'test'")
        print(f"{Colors.DIM}Suppress false positives: # codeguard:ignore{Colors.RESET}")
        
        return 0
    
    @staticmethod
    def cmd_scan(args):
        """Scan staged files"""
        Reporter.print_header()
        
        files = GitHelper.get_staged_files()
        
        if not files:
            if args.hook:
                # Running as hook, no files staged is fine
                return 0
            print("No staged files to scan")
            print("Stage files: git add <files>")
            return 0
        
        print()
        
        # Scan with progress
        detector = SecretDetector()
        scanner = FileScanner(detector)
        all_findings = []
        
        for i, filepath in enumerate(files, 1):
            Reporter.print_progress(i, len(files))
            
            content = GitHelper.get_staged_content(filepath)
            if content is None:
                continue
            
            findings = scanner.scan_file(filepath, content)
            all_findings.extend(findings)
        
        Reporter.clear_progress()
        
        # Report findings
        if all_findings:
            critical = [f for f in all_findings if f['severity'] == 'critical']
            high = [f for f in all_findings if f['severity'] == 'high']
            
            for finding in critical + high:
                Reporter.print_finding(finding)
            
            blocked = bool(critical or high)
            Reporter.print_summary(all_findings, blocked)
            
            return 1 if blocked else 0
        else:
            Reporter.print_summary([], False)
            return 0
    
    @staticmethod
    def cmd_scan_history(args):
        """Scan git commit history"""
        print(f"{Colors.CYAN}{Colors.BOLD}🔍 Scanning Git History{Colors.RESET}")
        print("━" * 60)
        print()
        
        if args.max_commits:
            print(f"Scanning last {args.max_commits} commits...")
        else:
            print("Scanning entire git history...")
        print()
        
        # Scan history
        detector = SecretDetector()
        findings = scan_repository_history(
            detector,
            max_commits=args.max_commits,
            max_workers=args.workers,
            show_progress=True
        )
        
        # Generate report
        if args.json:
            json_output = HistoryScanner.export_findings_json(findings)
            
            if args.output:
                Path(args.output).write_text(json_output)
                print(f"\nJSON report saved: {args.output}")
            else:
                print(json_output)
        else:
            report = HistoryScanner.generate_report(findings)
            
            if args.output:
                Path(args.output).write_text(report)
                print(f"\nReport saved: {args.output}")
            else:
                print(report)
        
        return 1 if findings else 0
    
    @staticmethod
    def cmd_config(args):
        """Show configuration"""
        config = ConfigManager.load_config()
        
        print(f"{Colors.CYAN}{Colors.BOLD}CodeGuard Configuration{Colors.RESET}")
        print("━" * 60)
        print(json.dumps(config, indent=2))
        
        print(f"\n{Colors.BOLD}Patterns:{Colors.RESET} {PATTERN_COUNT} total")
        for category, count in PATTERN_CATEGORIES.items():
            print(f"  {category}: {count}")
        
        config_file = Path(ConfigManager.CONFIG_FILE)
        if config_file.exists():
            print(f"\n{Colors.GREEN}Config: {config_file.absolute()}{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}Using defaults (run 'codeguard init' to customize){Colors.RESET}")
        
        return 0
    
    @staticmethod
    def cmd_uninstall(args):
        """Uninstall CodeGuard"""
        print(f"{Colors.YELLOW}Uninstalling CodeGuard...{Colors.RESET}")
        
        if not HookManager.uninstall_hook():
            return 1
        
        print("✓ Removed pre-commit hook")
        
        config_file = Path(ConfigManager.CONFIG_FILE)
        if config_file.exists():
            print(f"\nConfig file remains: {config_file}")
            print("Delete manually if desired: rm .codeguard.yml")
        
        print(f"\n{Colors.GREEN}CodeGuard uninstalled{Colors.RESET}")
        return 0
    
    @staticmethod
    def main():
        """Main entry point"""
        parser = argparse.ArgumentParser(
            description='CodeGuard - Pre-commit security scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
Examples:
  codeguard init                      Setup in repository
  codeguard scan                      Scan staged files
  codeguard scan-history              Scan all git history
  codeguard scan-history --max 100    Scan last 100 commits
  codeguard config                    Show configuration

Patterns: {PATTERN_COUNT} detection patterns loaded

Repository: https://github.com/yourusername/codeguard
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # init
        subparsers.add_parser('init', help='Initialize CodeGuard')
        
        # scan
        parser_scan = subparsers.add_parser('scan', help='Scan staged files')
        parser_scan.add_argument(
            '--hook',
            action='store_true',
            help='Internal: running as git hook'
        )
        
        # scan-history
        parser_history = subparsers.add_parser(
            'scan-history',
            help='Scan git commit history'
        )
        parser_history.add_argument(
            '--max-commits',
            type=int,
            metavar='N',
            help='Scan last N commits (default: all history)'
        )
        parser_history.add_argument(
            '--workers',
            type=int,
            default=4,
            metavar='N',
            help='Parallel workers (default: 4)'
        )
        parser_history.add_argument(
            '--json',
            action='store_true',
            help='Output as JSON'
        )
        parser_history.add_argument(
            '--output',
            '-o',
            metavar='FILE',
            help='Save report to file'
        )
        
        # config
        subparsers.add_parser('config', help='Show configuration')
        
        # uninstall
        subparsers.add_parser('uninstall', help='Uninstall CodeGuard')
        
        args = parser.parse_args()
        
        # Disable colors in CI/CD
        if os.getenv('CI') or not sys.stdout.isatty():
            Colors.disable_all()
        
        # Route to command
        if args.command == 'init':
            return CLI.cmd_init(args)
        elif args.command == 'scan':
            return CLI.cmd_scan(args)
        elif args.command == 'scan-history':
            return CLI.cmd_scan_history(args)
        elif args.command == 'config':
            return CLI.cmd_config(args)
        elif args.command == 'uninstall':
            return CLI.cmd_uninstall(args)
        else:
            parser.print_help()
            return 0


if __name__ == '__main__':
    try:
        sys.exit(CLI.main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted{Colors.RESET}")
        sys.exit(130)
    except Exception as error:
        print(f"{Colors.RED}Unexpected error: {error}{Colors.RESET}")
        if os.getenv('DEBUG'):
            import traceback
            traceback.print_exc()
        sys.exit(1)