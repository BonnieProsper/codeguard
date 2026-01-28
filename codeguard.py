#!/usr/bin/env python3
"""
CodeGuard - Pre-commit security scanner that prevents secrets from being committed
Blocks API keys, passwords, and tokens before they reach your repository

Usage:
    codeguard init              Setup in current repository
    codeguard scan              Manually scan staged files
    codeguard config            Show current configuration
    codeguard uninstall         Remove from repository

Author: Security-focused developers
License: MIT
Version: 1.0.0
"""

import os
import sys
import re
import argparse
import subprocess
import math
from pathlib import Path
from collections import Counter
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import json


# Terminal colors (fallback for systems without Rich)
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    @staticmethod
    def strip():
        """Disable colors (for CI/CD)"""
        for attr in dir(Colors):
            if not attr.startswith('_') and attr.isupper():
                setattr(Colors, attr, '')


# Try to use Rich for beautiful output, fall back gracefully
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _console = Console()
    USE_RICH = True
except ImportError:
    _console = None
    USE_RICH = False


def safe_print(text: str, style: str = ""):
    """Safe print that works with or without Rich"""
    if USE_RICH and _console is not None:
        _console.print(text)
    else:
        # Strip Rich markup for plain output
        import re
        clean_text = re.sub(r'\[.*?\]', '', text)
        print(clean_text)


class SecretPattern:
    """A pattern for detecting secrets"""
    
    def __init__(self, name: str, pattern: str, severity: str, 
                 confidence: int, fix_hint: str):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.confidence = confidence
        self.fix_hint = fix_hint
    
    def matches(self, text: str) -> List[Tuple[int, str]]:
        """Find all matches in text, return [(line_num, matched_text), ...]"""
        matches = []
        for line_num, line in enumerate(text.split('\n'), 1):
            for match in self.pattern.finditer(line):
                matches.append((line_num, match.group(0)))
        return matches


class SecretDetector:
    """Core secret detection engine"""
    
    # High confidence patterns - these are definitely secrets
    HIGH_CONFIDENCE_PATTERNS = [
        SecretPattern(
            'AWS Access Key',
            r'AKIA[0-9A-Z]{16}',
            'critical',
            100,
            'Use AWS IAM roles or environment variables. Never commit access keys.'
        ),
        SecretPattern(
            'GitHub Token',
            r'ghp_[a-zA-Z0-9]{36}',
            'critical',
            100,
            'Revoke at github.com/settings/tokens and use environment variables.'
        ),
        SecretPattern(
            'GitHub OAuth Token',
            r'gho_[a-zA-Z0-9]{36}',
            'critical',
            100,
            'Revoke OAuth token and regenerate with proper scoping.'
        ),
        SecretPattern(
            'Stripe Secret Key',
            r'sk_live_[a-zA-Z0-9]{24,}',
            'critical',
            100,
            'Use environment variables. Rotate key at dashboard.stripe.com'
        ),
        SecretPattern(
            'Stripe Restricted Key',
            r'rk_live_[a-zA-Z0-9]{24,}',
            'critical',
            100,
            'Rotate restricted key at dashboard.stripe.com'
        ),
        SecretPattern(
            'OpenAI API Key',
            r'sk-[a-zA-Z0-9]{48}',
            'critical',
            100,
            'Rotate key at platform.openai.com and use environment variables.'
        ),
        SecretPattern(
            'Slack Webhook',
            r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}',
            'high',
            100,
            'Regenerate webhook and store in environment variables.'
        ),
        SecretPattern(
            'Slack Token',
            r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
            'critical',
            100,
            'Revoke at api.slack.com/apps and regenerate.'
        ),
        SecretPattern(
            'Google Cloud API Key',
            r'AIza[0-9A-Za-z\\-_]{35}',
            'critical',
            100,
            'Restrict and rotate key in Google Cloud Console.'
        ),
        SecretPattern(
            'Google OAuth Token',
            r'ya29\.[0-9A-Za-z\-_]+',
            'critical',
            100,
            'Revoke OAuth token in Google Account settings.'
        ),
        SecretPattern(
            'Heroku API Key',
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'high',
            90,
            'Regenerate API key at dashboard.heroku.com/account'
        ),
        SecretPattern(
            'Twilio API Key',
            r'SK[0-9a-fA-F]{32}',
            'critical',
            100,
            'Revoke and regenerate at twilio.com/console'
        ),
        SecretPattern(
            'SendGrid API Key',
            r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            'critical',
            100,
            'Delete and create new key at app.sendgrid.com/settings/api_keys'
        ),
        SecretPattern(
            'MailChimp API Key',
            r'[0-9a-f]{32}-us[0-9]{1,2}',
            'high',
            95,
            'Regenerate key in MailChimp account settings.'
        ),
        SecretPattern(
            'Private SSH Key',
            r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'critical',
            100,
            'Remove private key. Generate new keypair if needed.'
        ),
        SecretPattern(
            'PGP Private Key',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'critical',
            100,
            'Remove private key immediately. Generate new if compromised.'
        ),
    ]
    
    # Medium confidence - need context checking
    MEDIUM_CONFIDENCE_PATTERNS = [
        SecretPattern(
            'Generic API Key',
            r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            'high',
            80,
            'Use environment variables: API_KEY=os.getenv("API_KEY")'
        ),
        SecretPattern(
            'Generic Secret',
            r'(?:secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            'high',
            75,
            'Store in environment variables or secrets manager.'
        ),
        SecretPattern(
            'Password in Code',
            r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
            'high',
            70,
            'Never hardcode passwords. Use environment variables.'
        ),
        SecretPattern(
            'Database Connection String',
            r'(?:mongodb|mysql|postgres|postgresql)://[^\s:]+:[^\s@]+@',
            'high',
            85,
            'Use environment variables for database URLs.'
        ),
        SecretPattern(
            'JWT Token',
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
            'medium',
            60,
            'JWT tokens should not be committed. Use secure storage.'
        ),
    ]
    
    def __init__(self):
        self.patterns = (
            self.HIGH_CONFIDENCE_PATTERNS + 
            self.MEDIUM_CONFIDENCE_PATTERNS
        )
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy - higher means more random"""
        if not text or len(text) < 8:
            return 0.0
        
        counts = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )
        return entropy
    
    @staticmethod
    def is_test_file(filepath: str) -> bool:
        """Check if file is a test/example file"""
        test_indicators = [
            'test', 'spec', 'fixture', 'mock', 'example',
            'sample', 'demo', '__tests__', '.test.', '.spec.',
            '_test.', '_spec.', 'examples/', 'fixtures/',
        ]
        filepath_lower = filepath.lower()
        return any(indicator in filepath_lower for indicator in test_indicators)
    
    @staticmethod
    def is_placeholder(value: str) -> bool:
        """Check if value is a placeholder"""
        placeholders = [
            'your_key_here', 'your_secret_here', 'your_token_here',
            'example', 'placeholder', 'replace_me', 'changeme',
            'xxx', '***', 'yyy', 'zzz', 'todo', 'fixme',
            'your-api-key', 'your-secret', 'insert-key-here',
            '12345', 'abcdef', 'test', 'demo', 'sample',
        ]
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders)
    
    @staticmethod
    def is_in_comment(line: str) -> bool:
        """Check if line is a comment"""
        stripped = line.strip()
        comment_starts = ['#', '//', '/*', '*', '--', '<!--']
        return any(stripped.startswith(c) for c in comment_starts)
    
    def is_likely_secret(self, value: str, filepath: str, line: str, 
                        confidence: int) -> bool:
        """Context-aware secret detection to reduce false positives"""
        
        # High confidence patterns always fire
        if confidence >= 95:
            return True
        
        # Test files get lower scrutiny
        if self.is_test_file(filepath):
            return False
        
        # Placeholders are not secrets
        if self.is_placeholder(value):
            return False
        
        # Comments are less likely to contain real secrets
        if self.is_in_comment(line):
            return False
        
        # Check entropy (random strings more likely to be secrets)
        entropy = self.calculate_entropy(value)
        if entropy < 2.5:  # Low randomness
            return False
        
        # Short values are less likely to be secrets
        if len(value) < 12:
            return False
        
        return True
    
    def scan_content(self, content: str, filepath: str) -> List[Dict]:
        """Scan content for secrets"""
        findings = []
        
        for pattern in self.patterns:
            matches = pattern.matches(content)
            
            for line_num, matched_value in matches:
                # Get the actual line
                lines = content.split('\n')
                line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                
                # Context-aware filtering
                if not self.is_likely_secret(
                    matched_value, filepath, line_content, pattern.confidence
                ):
                    continue
                
                # Get context lines (3 before, 3 after)
                start_line = max(0, line_num - 3)
                end_line = min(len(lines), line_num + 3)
                context = lines[start_line:end_line]
                
                findings.append({
                    'pattern_name': pattern.name,
                    'severity': pattern.severity,
                    'confidence': pattern.confidence,
                    'filepath': filepath,
                    'line_number': line_num,
                    'matched_value': matched_value,
                    'line_content': line_content,
                    'context_lines': context,
                    'fix_hint': pattern.fix_hint,
                    'entropy': self.calculate_entropy(matched_value),
                })
        
        return findings


class GitHelper:
    """Helper for Git operations"""
    
    @staticmethod
    def is_git_repo() -> bool:
        """Check if current directory is a git repository"""
        return Path('.git').exists()
    
    @staticmethod
    def get_staged_files() -> List[str]:
        """Get list of staged files"""
        try:
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
            return files
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return []
    
    @staticmethod
    def get_staged_content(filepath: str) -> Optional[str]:
        """Get staged content of a file"""
        try:
            result = subprocess.run(
                ['git', 'show', f':{filepath}'],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            return result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, UnicodeDecodeError):
            # File might be binary or deleted
            return None


class FileScanner:
    """Scans files for secrets"""
    
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    def __init__(self, detector: SecretDetector):
        self.detector = detector
    
    @staticmethod
    def is_binary(filepath: str) -> bool:
        """Quick binary file detection"""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(8192)
                return b'\x00' in chunk
        except:
            return True
    
    @staticmethod
    def should_skip(filepath: str) -> Tuple[bool, Optional[str]]:
        """Determine if file should be skipped"""
        path = Path(filepath)
        
        # Check if exists
        if not path.exists():
            return True, "File doesn't exist"
        
        # Check size
        try:
            size = path.stat().st_size
            if size == 0:
                return True, "Empty file"
            if size > FileScanner.MAX_FILE_SIZE:
                return True, f"File too large ({size / 1024 / 1024:.1f}MB)"
        except:
            return True, "Cannot read file stats"
        
        # Check if binary
        if FileScanner.is_binary(filepath):
            return True, "Binary file"
        
        return False, None
    
    def scan_file(self, filepath: str, content: Optional[str] = None) -> List[Dict]:
        """Scan a single file"""
        # Get content if not provided
        if content is None:
            should_skip, reason = self.should_skip(filepath)
            if should_skip:
                return []
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception:
                return []
        
        return self.detector.scan_content(content, filepath)


class Reporter:
    """Reports findings to user"""
    
    @staticmethod
    def print_header():
        """Print scan header"""
        if USE_RICH and _console is not None:
            _console.print("\n[bold cyan]🛡️  CodeGuard Security Scan[/bold cyan]")
            _console.print("━" * 50)
        else:
            print(f"\n{Colors.CYAN}{Colors.BOLD}🛡️  CodeGuard Security Scan{Colors.RESET}")
            print("━" * 50)
    
    @staticmethod
    def print_finding(finding: Dict, show_context: bool = True):
        """Print a single finding"""
        if USE_RICH and _console is not None:
            Reporter._print_finding_rich(finding, show_context)
        else:
            Reporter._print_finding_plain(finding, show_context)
    
    @staticmethod
    def _print_finding_rich(finding: Dict, show_context: bool):
        """Rich formatting"""
        if _console is None:
            return
        
        # File location
        _console.print(f"\n[bold]{finding['filepath']}:{finding['line_number']}[/bold]")
        
        # Context
        if show_context and finding.get('context_lines'):
            start_line = finding['line_number'] - len(finding['context_lines']) // 2
            for i, line in enumerate(finding['context_lines']):
                line_num = start_line + i
                if line_num == finding['line_number']:
                    # Highlight the problematic line
                    _console.print(f"[red]{line_num:4} | {line}[/red]")
                else:
                    _console.print(f"{line_num:4} | {line}")
        
        _console.print()
        
        # Details
        severity_colors = {
            'critical': 'red',
            'high': 'yellow',
            'medium': 'blue',
            'low': 'green'
        }
        color = severity_colors.get(finding['severity'], 'white')
        
        _console.print(f"[{color}]⚠️  {finding['pattern_name']}[/{color}]")
        _console.print(f"[dim]Confidence: {finding['confidence']}% | Entropy: {finding['entropy']:.2f}[/dim]")
        _console.print(f"💡 [bold]Fix:[/bold] {finding['fix_hint']}")
        _console.print()
    
    @staticmethod
    def _print_finding_plain(finding: Dict, show_context: bool):
        """Plain text formatting"""
        # File location
        print(f"\n{Colors.BOLD}{finding['filepath']}:{finding['line_number']}{Colors.RESET}")
        
        # Context
        if show_context and finding.get('context_lines'):
            start_line = finding['line_number'] - len(finding['context_lines']) // 2
            for i, line in enumerate(finding['context_lines']):
                line_num = start_line + i
                if line_num == finding['line_number']:
                    print(f"{Colors.RED}{line_num:4} | {line}{Colors.RESET}")
                else:
                    print(f"{line_num:4} | {line}")
        
        print()
        
        # Details
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.YELLOW,
            'medium': Colors.BLUE,
            'low': Colors.GREEN
        }
        color = severity_colors.get(finding['severity'], '')
        
        print(f"{color}⚠️  {finding['pattern_name']}{Colors.RESET}")
        print(f"Confidence: {finding['confidence']}% | Entropy: {finding['entropy']:.2f}")
        print(f"💡 Fix: {finding['fix_hint']}")
        print()
    
    @staticmethod
    def print_summary(findings: List[Dict], blocked: bool):
        """Print summary"""
        critical = sum(1 for f in findings if f['severity'] == 'critical')
        high = sum(1 for f in findings if f['severity'] == 'high')
        medium = sum(1 for f in findings if f['severity'] == 'medium')
        
        if USE_RICH and _console is not None:
            if blocked:
                _console.print(f"\n[bold red]❌ COMMIT BLOCKED[/bold red]")
                _console.print(f"Found {len(findings)} secret(s): {critical} critical, {high} high, {medium} medium")
                _console.print("\n[yellow]Fix the issues above before committing.[/yellow]")
                _console.print("Docs: https://github.com/yourusername/codeguard")
            else:
                _console.print(f"\n[bold green]✅ No secrets detected[/bold green]")
                _console.print("Safe to commit!")
        else:
            if blocked:
                print(f"\n{Colors.RED}{Colors.BOLD}❌ COMMIT BLOCKED{Colors.RESET}")
                print(f"Found {len(findings)} secret(s): {critical} critical, {high} high, {medium} medium")
                print(f"\n{Colors.YELLOW}Fix the issues above before committing.{Colors.RESET}")
                print("Docs: https://github.com/yourusername/codeguard")
            else:
                print(f"\n{Colors.GREEN}{Colors.BOLD}✅ No secrets detected{Colors.RESET}")
                print("Safe to commit!")


class ConfigManager:
    """Manages CodeGuard configuration"""
    
    DEFAULT_CONFIG = {
        'version': 1,
        'rules': {
            'high_confidence': {
                'enabled': True,
                'min_confidence': 95,
            },
            'medium_confidence': {
                'enabled': True,
                'min_confidence': 70,
            },
        },
        'ignore': {
            'paths': [
                'test/**',
                'tests/**',
                'spec/**',
                'examples/**',
                '*.test.*',
                '*.spec.*',
            ],
        },
        'performance': {
            'max_file_size_mb': 10,
        }
    }
    
    CONFIG_FILE = '.codeguard.yml'
    
    @classmethod
    def load_config(cls) -> Dict:
        """Load configuration"""
        if not Path(cls.CONFIG_FILE).exists():
            return cls.DEFAULT_CONFIG.copy()
        
        try:
            import yaml
            with open(cls.CONFIG_FILE, 'r') as f:
                user_config = yaml.safe_load(f) or {}
            
            # Merge with defaults
            config = cls.DEFAULT_CONFIG.copy()
            config.update(user_config)
            return config
        except ImportError:
            # PyYAML not installed, use defaults
            return cls.DEFAULT_CONFIG.copy()
        except Exception:
            # Error reading config, use defaults
            return cls.DEFAULT_CONFIG.copy()
    
    @classmethod
    def create_default_config(cls, project_type: str = 'generic'):
        """Create default config file"""
        config_content = f"""# CodeGuard Configuration
# https://codeguard.dev/docs/configuration

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

# Performance settings
performance:
  max_file_size_mb: 10

# Project type: {project_type}
"""
        
        with open(cls.CONFIG_FILE, 'w') as f:
            f.write(config_content)


class HookManager:
    """Manages git hooks"""
    
    HOOK_PATH = Path('.git/hooks/pre-commit')
    HOOK_CONTENT = '''#!/bin/sh
# CodeGuard pre-commit hook
# Auto-generated - do not edit manually

# Run CodeGuard scan
codeguard scan --hook

# Exit with CodeGuard's exit code
exit $?
'''
    
    @classmethod
    def install_hook(cls) -> bool:
        """Install pre-commit hook"""
        hook_path = cls.HOOK_PATH
        
        # Create hooks directory if needed
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Backup existing hook
        if hook_path.exists():
            backup_path = Path(f"{hook_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            try:
                hook_path.rename(backup_path)
                print(f"Backed up existing hook to: {backup_path.name}")
            except Exception as e:
                print(f"Warning: Could not backup existing hook: {e}")
                return False
        
        # Write new hook
        try:
            hook_path.write_text(cls.HOOK_CONTENT)
            hook_path.chmod(0o755)  # Make executable
            return True
        except Exception as e:
            print(f"Error installing hook: {e}")
            return False
    
    @classmethod
    def uninstall_hook(cls) -> bool:
        """Uninstall pre-commit hook"""
        hook_path = cls.HOOK_PATH
        
        if not hook_path.exists():
            return True
        
        # Check if it's our hook
        try:
            content = hook_path.read_text()
            if 'CodeGuard' not in content:
                print("Warning: pre-commit hook exists but doesn't appear to be CodeGuard's")
                return False
            
            # Remove hook
            hook_path.unlink()
            
            # Restore backup if exists
            backups = sorted(hook_path.parent.glob(f"{hook_path.name}.backup.*"))
            if backups:
                latest_backup = backups[-1]
                latest_backup.rename(hook_path)
                print(f"Restored backup: {latest_backup.name}")
            
            return True
        except Exception as e:
            print(f"Error uninstalling hook: {e}")
            return False


class CLI:
    """Command-line interface"""
    
    @staticmethod
    def cmd_init(args):
        """Initialize CodeGuard in repository"""
        # Check if git repo
        if not GitHelper.is_git_repo():
            print(f"{Colors.RED}❌ Not a git repository{Colors.RESET}")
            print("Run: git init")
            return 1
        
        print(f"{Colors.CYAN}{Colors.BOLD}🛡️  CodeGuard Setup{Colors.RESET}")
        print("━" * 50)
        
        # Create config
        project_type = 'generic'  # Could auto-detect
        ConfigManager.create_default_config(project_type)
        print("✓ Created .codeguard.yml")
        
        # Install hook
        if HookManager.install_hook():
            print("✓ Installed pre-commit hook")
        else:
            print(f"{Colors.RED}✗ Failed to install pre-commit hook{Colors.RESET}")
            return 1
        
        # Success
        print(f"\n{Colors.GREEN}🎉 Setup complete!{Colors.RESET}")
        print("\nCodeGuard will now scan every commit automatically.")
        print(f"\n{Colors.BOLD}Try it:{Colors.RESET} git add . && git commit -m 'test'")
        print(f"\n{Colors.DIM}Docs: https://codeguard.dev/docs{Colors.RESET}")
        
        return 0
    
    @staticmethod
    def cmd_scan(args):
        """Scan staged files"""
        Reporter.print_header()
        
        # Get staged files
        files = GitHelper.get_staged_files()
        
        if not files:
            if args.hook:
                # In hook mode, no files is success
                return 0
            else:
                print("No staged files to scan.")
                print("Run: git add <files>")
                return 0
        
        print(f"Scanning {len(files)} file(s)...\n")
        
        # Scan files
        detector = SecretDetector()
        scanner = FileScanner(detector)
        all_findings = []
        
        for filepath in files:
            # Get staged content (not working directory)
            content = GitHelper.get_staged_content(filepath)
            if content is None:
                continue
            
            findings = scanner.scan_file(filepath, content)
            all_findings.extend(findings)
        
        # Report findings
        if all_findings:
            # Group by severity
            critical = [f for f in all_findings if f['severity'] == 'critical']
            high = [f for f in all_findings if f['severity'] == 'high']
            medium = [f for f in all_findings if f['severity'] == 'medium']
            
            # Show critical/high findings
            for finding in critical + high:
                Reporter.print_finding(finding)
            
            # Summary
            blocked = bool(critical or high)
            Reporter.print_summary(all_findings, blocked)
            
            # Return appropriate exit code
            if blocked:
                return 1  # Block commit
            else:
                return 0  # Allow but warn
        else:
            Reporter.print_summary([], False)
            return 0
    
    @staticmethod
    def cmd_config(args):
        """Show configuration"""
        config = ConfigManager.load_config()
        
        print(f"{Colors.CYAN}{Colors.BOLD}CodeGuard Configuration{Colors.RESET}")
        print("━" * 50)
        print(json.dumps(config, indent=2))
        
        config_file = Path(ConfigManager.CONFIG_FILE)
        if config_file.exists():
            print(f"\n{Colors.GREEN}Using: {config_file.absolute()}{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}Using default configuration{Colors.RESET}")
            print(f"Run 'codeguard init' to create {ConfigManager.CONFIG_FILE}")
        
        return 0
    
    @staticmethod
    def cmd_uninstall(args):
        """Uninstall CodeGuard"""
        print(f"{Colors.YELLOW}Uninstalling CodeGuard...{Colors.RESET}")
        
        if HookManager.uninstall_hook():
            print("✓ Removed pre-commit hook")
        else:
            print(f"{Colors.RED}✗ Failed to remove pre-commit hook{Colors.RESET}")
            return 1
        
        # Ask about config
        config_file = Path(ConfigManager.CONFIG_FILE)
        if config_file.exists():
            print(f"\nConfig file still exists: {config_file}")
            print("Remove manually if desired: rm .codeguard.yml")
        
        print(f"\n{Colors.GREEN}CodeGuard uninstalled{Colors.RESET}")
        return 0
    
    @staticmethod
    def main():
        """Main entry point"""
        parser = argparse.ArgumentParser(
            description='CodeGuard - Pre-commit security scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  codeguard init              Setup in current repository
  codeguard scan              Manually scan staged files
  codeguard config            Show configuration
  codeguard uninstall         Remove from repository

For more help: https://codeguard.dev/docs
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Init command
        parser_init = subparsers.add_parser('init', help='Initialize CodeGuard')
        
        # Scan command
        parser_scan = subparsers.add_parser('scan', help='Scan staged files')
        parser_scan.add_argument('--hook', action='store_true', 
                               help='Running as git hook (internal use)')
        
        # Config command
        parser_config = subparsers.add_parser('config', help='Show configuration')
        
        # Uninstall command
        parser_uninstall = subparsers.add_parser('uninstall', help='Uninstall CodeGuard')
        
        # Parse args
        args = parser.parse_args()
        
        # Disable colors in CI/CD
        if os.getenv('CI') or not sys.stdout.isatty():
            Colors.strip()
        
        # Route to command
        if args.command == 'init':
            return CLI.cmd_init(args)
        elif args.command == 'scan':
            return CLI.cmd_scan(args)
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
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)