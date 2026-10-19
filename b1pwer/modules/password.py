"""
b1pwer.modules.password - Password strength & breach audit
"""
import re
import math
import os
from dataclasses import dataclass, field


@dataclass
class PasswordReport:
    password: str
    length: int
    entropy: float
    crack_time: str
    score: int
    in_breach: bool = False
    issues: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)


class PasswordAuditor:
    def __init__(self, wordlist_path: str = ""):
        self.wordlist_path = wordlist_path or self._find_rockyou()
        self.breach_set = set()
        self._load_sample()

    def _find_rockyou(self) -> str:
        for path in [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/b1pwer/assets/wordlists/rockyou_top3m.txt",
            os.path.expanduser("~/b1pwer/b1pwer-deb/usr/share/b1pwer/assets/wordlists/rockyou_top3m.txt"),
        ]:
            if os.path.isfile(path):
                return path
        return ""

    def _load_sample(self):
        if not self.wordlist_path:
            return
        try:
            with open(self.wordlist_path, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= 500000:
                        break
                    self.breach_set.add(line.strip())
        except:
            pass

    def audit(self, password: str) -> PasswordReport:
        report = PasswordReport(
            password=password,
            length=len(password),
            entropy=0, crack_time="", score=0, issues=[], suggestions=[]
        )

        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"[0-9]", password):
            charset_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 32

        report.entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0

        report.in_breach = password.lower() in self.breach_set

        report.issues = self._find_issues(password)
        report.suggestions = self._suggest(password, report.issues)
        report.score = self._score(password, report)

        guesses_per_sec = 1e10
        combinations = charset_size ** len(password) if charset_size > 0 else 1
        seconds = combinations / (2 * guesses_per_sec)
        report.crack_time = self._human_time(seconds)

        return report

    def _find_issues(self, p: str) -> list:
        issues = []
        if len(p) < 8:
            issues.append("Too short (under 8 characters)")
        if not re.search(r"[A-Z]", p):
            issues.append("No uppercase letters")
        if not re.search(r"[0-9]", p):
            issues.append("No numbers")
        if not re.search(r"[^a-zA-Z0-9]", p):
            issues.append("No special characters")
        if re.search(r"(.)\1{2,}", p):
            issues.append("Repeated characters")
        if re.search(r"(123|abc|qwe|password|admin|letmein)", p.lower()):
            issues.append("Common pattern detected")
        if p.lower() in self.breach_set:
            issues.append("FOUND IN BREACHED PASSWORD DATABASE")
        return issues

    def _suggest(self, p: str, issues: list) -> list:
        suggestions = []
        if len(p) < 12:
            suggestions.append("Use at least 12 characters")
        if not re.search(r"[^a-zA-Z0-9]", p):
            suggestions.append("Add special characters (!@#$%)")
        if not re.search(r"[A-Z]", p):
            suggestions.append("Mix uppercase and lowercase")
        if "BREACHED" in str(issues):
            suggestions.append("DO NOT use this password - it has been leaked")
        suggestions.append("Use a passphrase: 4+ random words")
        return suggestions

    def _score(self, p: str, report: PasswordReport) -> int:
        score = 100
        if report.length < 8:
            score -= 40
        elif report.length < 12:
            score -= 20
        if report.in_breach:
            score -= 50
        if not re.search(r"[A-Z]", p):
            score -= 10
        if not re.search(r"[0-9]", p):
            score -= 10
        if not re.search(r"[^a-zA-Z0-9]", p):
            score -= 10
        return max(0, min(100, score))

    def _human_time(self, seconds: float) -> str:
        if seconds < 1:
            return "instantly"
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        if seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        if seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        if seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        if seconds < 31536000 * 1000:
            return f"{seconds/31536000:.0f} years"
        if seconds < 31536000 * 1e6:
            return f"{seconds/(31536000*1000):.0f} thousand years"
        if seconds < 31536000 * 1e9:
            return f"{seconds/(31536000*1e6):.0f} million years"
        return "billions of years"
