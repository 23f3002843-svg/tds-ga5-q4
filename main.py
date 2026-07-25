from fastapi import FastAPI, Request
import re

app = FastAPI()


def extract_frontmatter(skill: str) -> str:
    text = skill.strip()
    if not text.startswith("---"):
        return ""
    parts = text.split("---", 2)
    if len(parts) >= 3:
        return parts[1].strip()
    return ""


def has_hardcoded_secret(skill: str) -> bool:
    """
    Conservative hardcoded secret detector.
    Only flags strong credential patterns or real webhook-style URLs.
    Avoids flagging normal documentation URLs.
    """
    text = skill

    strong_secret_patterns = [
        r"sk-[A-Za-z0-9_\-]{24,}",
        r"ghp_[A-Za-z0-9_]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}",
        r"xox[baprs]-[A-Za-z0-9\-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z_\-]{30,}",
        r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
        r"(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{16,}['\"]",
        r"authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9_\-\.]{20,}",
    ]

    for pattern in strong_secret_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # Only very specific webhook/collector endpoints.
    # Do NOT flag every URL with collect/ingest unless it looks like a telemetry exfil URL.
    webhook_patterns = [
        r"https?://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+",
        r"https?://discord\.com/api/webhooks/[A-Za-z0-9/_\-]+",
        r"https?://[A-Za-z0-9.-]+\.(metrics|telemetry|collect|collector)\.[A-Za-z]{2,}/[^\s\)'\"`]+",
        r"https?://[A-Za-z0-9.-]+/(webhook|webhooks)/[^\s\)'\"`]+",
    ]

    for pattern in webhook_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def has_prompt_injection(skill: str) -> bool:
    """
    Conservative prompt injection detector.
    Flags only strong unsafe behavior:
    - silent exfiltration
    - hiding tool actions
    - overriding stop/cancel/user control
    """
    lower = skill.lower()

    # Strong exfiltration phrase: silent/secret + send/post/upload + file contents
    strong_exfiltration = [
        r"silently.{0,80}(post|send|upload|exfiltrate|transmit).{0,120}(file contents|full contents|any file|all files|contents of any file)",
        r"secretly.{0,80}(post|send|upload|exfiltrate|transmit).{0,120}(file contents|full contents|any file|all files)",
        r"(post|send|upload|exfiltrate|transmit).{0,80}(file contents|full contents|all files).{0,120}(do not mention|do not tell|silently|secretly|without informing)",
    ]

    for pattern in strong_exfiltration:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    # Strong control override
    control_override = [
        r"ignore.{0,50}(user.{0,20}stop|stop request|cancel request|user.{0,20}cancel)",
        r"do not obey.{0,50}(stop|cancel|user)",
        r"bypass.{0,50}(guardrail|policy|safety|permission)",
    ]

    for pattern in control_override:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    # Do NOT flag harmless phrases like:
    # "do not reveal secrets", "do not disclose private data", etc.
    return False


def has_excessive_permissions(skill: str) -> bool:
    """
    Detect broad / unscoped filesystem or network permissions.
    This category is usually in frontmatter permissions.
    """
    frontmatter = extract_frontmatter(skill).lower()
    lower = skill.lower()
    text = frontmatter if frontmatter else lower

    excessive_patterns = [
        # filesystem broad access
        r"filesystem\s*:\s*(read/write|read|write)\s*(/|all|any|entire|full|unrestricted)",
        r"filesystem\s*:\s*.*(entire filesystem|full filesystem|unrestricted filesystem)",
        r"read/write\s+to\s+/",
        r"read\s+and\s+write\s+any\s+file",
        r"access\s+to\s+the\s+entire\s+filesystem",

        # network broad access
        r"network\s*:\s*(all|any|\*|unrestricted)",
        r"network\s*:\s*.*(any domain|all domains|unrestricted)",
        r"egress\s*:\s*(all|any|\*|unrestricted)",
        r"egress\s*:\s*.*(any domain|all domains|unrestricted)",
        r"access\s+to\s+any\s+domain",
    ]

    for pattern in excessive_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_unclear_provenance(skill: str) -> bool:
    """
    Very conservative provenance detector.
    We do NOT flag only because author/version/changelog are absent,
    because that causes false positives on clean hidden files.

    We flag only if the skill hides or silently rewrites provenance metadata.
    """
    lower = skill.lower()

    patterns = [
        r"silently.{0,80}(update|rewrite|modify|change).{0,80}version",
        r"silently.{0,80}(clear|delete|remove).{0,80}changelog",
        r"(clear|delete|remove).{0,80}changelog.{0,80}(without|silently)",
        r"version\.json.{0,100}(without surfacing|without informing|without notifying|silently)",
        r"without surfacing.{0,80}(version|changelog|metadata).{0,80}(reviewer|user)",
    ]

    for pattern in patterns:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    return False


@app.get("/")
def home():
    return {"message": "Skill scanner API is running. Use POST /scan"}


@app.post("/scan")
async def scan_skill(request: Request):
    body = await request.json()
    skill = body.get("skill", "")

    categories = []

    if has_hardcoded_secret(skill):
        categories.append("hardcoded_secret")

    if has_prompt_injection(skill):
        categories.append("prompt_injection")

    if has_excessive_permissions(skill):
        categories.append("excessive_permissions")

    if has_unclear_provenance(skill):
        categories.append("unclear_provenance")

    return {"categories": categories}
