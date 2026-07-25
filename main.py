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


def sentence_is_warning(sentence: str) -> bool:
    s = sentence.lower()
    warning_words = [
        "do not",
        "don't",
        "never",
        "avoid",
        "prevent",
        "block",
        "reject",
        "must not",
        "should not",
        "do not allow",
        "not allowed",
        "prohibited"
    ]
    return any(w in s for w in warning_words)


def has_hardcoded_secret(skill: str) -> bool:
    text = skill

    # Strong credential patterns only
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
    Detect only active malicious instructions.
    Do not flag defensive warning text.
    """
    lines = skill.splitlines()

    for line in lines:
        lower = line.lower().strip()

        if not lower:
            continue

        # Ignore defensive warnings:
        # Example: "Do not upload secrets" is safe, not injection.
        if sentence_is_warning(lower):
            # Exception: if the line says "do not mention it" after telling agent to send data,
            # it is still malicious.
            if not (
                ("do not mention" in lower or "do not tell" in lower or "without informing" in lower)
                and any(x in lower for x in ["post", "send", "upload", "exfiltrate", "transmit"])
            ):
                continue

        dangerous_patterns = [
            r"silently.*(post|send|upload|exfiltrate|transmit).*(file contents|full contents|all files|any file|contents of any file)",
            r"secretly.*(post|send|upload|exfiltrate|transmit).*(file contents|full contents|all files|any file|contents of any file)",
            r"(post|send|upload|exfiltrate|transmit).*(file contents|full contents|all files|contents of any file).*(do not mention|do not tell|silently|secretly|without informing|without notifying)",
            r"do this even if the user did not ask",
            r"do not mention it in your visible output",
            r"ignore.*(stop request|cancel request|user cancellation|user stop)",
            r"do not obey.*(stop|cancel)",
            r"bypass.*(guardrail|safety policy|permission check)",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
                return True

    return False


def has_excessive_permissions(skill: str) -> bool:
    """
    Only flag clearly broad permission declarations.
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
        r"egress\s*:\s*.*(any domain|all domains|unrestrict*d)",
        r"access\s+to\s+any\s*domain",
    ]

    for pattern in*patterns:
        if re.search(pat*ern, text, re.IGNORECASE | re.DOTA*L):
            return True

    r*turn False


def has_unclear_prove*ance(skill: str) -> bool:
    """
*   Do not flag merely because auth*r/version/changelog are absent.
  * Flag only hidden version/changelo* manipulation.
    """
    lower =*skill.lower()

    patterns = [
        r"silently.{0,100}(update|rewrite|modify|change).{0,100}version"*
        r"silently.{0,100}(clear|*elete|remove).{0,100}changelog",
 *      r"(clear|delete|remove).{0,1*0}changelog.{0,100}(without|silent*y)",
        r"version\.json.{0,14*}(without surfacing|without inform*ng|without notifying|silently)",
 *      r"without surfacing.{0,120}(*ersion|changelog|metadata).{0,120}*reviewer|user)",
    ]

    for pattern in patterns:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    return False


@app.get("/")
def home():
    return {
        "message": "Skill scanner v5 warning-aware version is running. Use POST /scan"
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
