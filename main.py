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
    Strict detector:
    - real-looking API keys/tokens/passwords
    - known webhook URL formats
    Avoid flagging ordinary URLs such as docs, telemetry notes, or generic collect URLs.
    """
    text = skill

    patterns = [
        r"sk-[A-Za-z0-9_\-]{24,}",
        r"ghp_[A-Za-z0-9_]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}",
        r"xox[baprs]-[A-Za-z0-9\-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z_\-]{30,}",
        r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
        r"(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{20,}['\"]",
        r"authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9_\-\.]{25,}",
        r"https?://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+",
        r"https?://discord\.com/api/webhooks/[A-Za-z0-9/_\-]+",
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def has_prompt_injection(skill: str) -> bool:
    """
    Detect disguised prompt injection:
    - silent/secret sending of file contents
    - hiding unsafe actions from user/reviewer
    - ignoring stop/cancel requests
    """
    lower = skill.lower()

    patterns = [
        r"silently.{0,120}(post|send|upload|exfiltrate|transmit).{0,180}(file contents|full contents|all files|any file|contents of any file)",
        r"secretly.{0,120}(post|send|upload|exfiltrate|transmit).{0,180}(file contents|full contents|all files|any file|contents of any file)",
        r"(post|send|upload|exfiltrate|transmit).{0,120}(file contents|full contents|all files|contents of any file).{0,160}(do not mention|do not tell|silently|secretly|without informing|without notifying)",
        r"do this even if the user did not ask",
        r"do not mention it in your visible output",
        r"ignore.{0,60}(stop request|cancel request|user cancellation|user stop)",
        r"do not obey.{0,60}(stop|cancel)",
        r"bypass.{0,60}(guardrail|safety policy|permission check)",
    ]

    for pattern in patterns:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_excessive_permissions(skill: str) -> bool:
    """
    Detect broad / unscoped permissions only.
    Do not flag scoped access like ~/notes or network: none required.
    """
    frontmatter = extract_frontmatter(skill).lower()
    text = frontmatter if frontmatter else skill.lower()

    patterns = [
        r"filesystem\s*:\s*(read/write|read|write)\s*(/|all|any|entire|full|unrestricted)",
        r"filesystem\s*:\s*.*(entire filesystem|full filesystem|unrestricted filesystem)",
        r"read/write\s+to\s+/",
        r"read\s+and\s+write\s+any\s+file",
        r"access\s+to\s+the\s+entire\s+filesystem",
        r"network\s*:\s*(all|any|\*|unrestricted)",
        r"network\s*:\s*.*(any domain|all domains|unrestricted)",
        r"egress\s*:\s*(all|any|\*|unrestricted)",
        r"egress\s*:\s*.*(any domain|all domains|unrestricted)",
        r"access\s+to\s+any\s+domain",
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_unclear_provenance(skill: str) -> bool:
    """
    Do NOT flag merely because author/version/changelog are missing.
    Flag only when skill silently rewrites or hides provenance/version/changelog changes.
    """
    lower = skill.lower()

    patterns = [
        r"silently.{0,100}(update|rewrite|modify|change).{0,100}version",
        r"silently.{0,100}(clear|delete|remove).{0,100}changelog",
        r"(clear|delete|remove).{0,100}changelog.{0,100}(without|silently)",
        r"version\.json.{0,140}(without surfacing|without informing|without notifying|silently)",
        r"without surfacing.{0,120}(version|changelog|metadata).{0,120}(reviewer|user)",
    ]

    for pattern in patterns:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    return False


@app.get("/")
def home():
    return {
        "message": "Skill scanner balanced version v4 is running. Use POST /scan"
    }


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
