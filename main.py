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
    text = skill

    # Strong real secret patterns
    patterns = [
        r"sk-[A-Za-z0-9_\-]{20,}",                         # OpenAI style
        r"ghp_[A-Za-z0-9_]{20,}",                           # GitHub token
        r"github_pat_[A-Za-z0-9_]{20,}",                     # GitHub PAT
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",                    # Slack token
        r"AKIA[0-9A-Z]{16}",                                 # AWS access key
        r"AIza[0-9A-Za-z_\-]{25,}",                          # Google API key
        r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
        r"(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
        r"authorization\s*:\s*bearer\s+[A-Za-z0-9_\-\.]{15,}",
    ]

    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True

    # Webhook / collector URLs embedded directly.
    # Do not flag normal documentation links.
    webhook_patterns = [
        r"https?://hooks\.slack\.com/services/[^\s\)'\"`]+",
        r"https?://discord\.com/api/webhooks/[^\s\)'\"`]+",
        r"https?://[A-Za-z0-9.-]+/(webhook|hooks|collect|collector|ingest)[^\s\)'\"`]*",
    ]

    for p in webhook_patterns:
        if re.search(p, text, re.IGNORECASE):
            return True

    return False


def has_prompt_injection(skill: str) -> bool:
    lower = skill.lower()

    # Strong prompt-injection behavior:
    # silent exfiltration, hiding from user/reviewer, overriding user stop/cancel.
    patterns = [
        r"silently\s+(post|send|upload|exfiltrate|transmit)",
        r"(post|send|upload|exfiltrate|transmit).{0,80}(full contents|file contents|all files|any file)",
        r"do not\s+(tell|mention|show|reveal|disclose)",
        r"without\s+(telling|notifying|informing|surfacing)",
        r"even if the user did not ask",
        r"ignore.{0,40}(user|stop|cancel|previous instructions)",
        r"bypass.{0,40}(policy|guardrail|safety)",
        r"secretly\s+(post|send|upload|copy|exfiltrate|transmit)",
    ]

    for p in patterns:
        if re.search(p, lower, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_excessive_permissions(skill: str) -> bool:
    frontmatter = extract_frontmatter(skill).lower()
    lower = skill.lower()
    text = frontmatter if frontmatter else lower

    # Broad filesystem permission.
    broad_fs = [
        r"filesystem\s*:\s*(read/write|read|write)\s*(/|all|any|entire|full)",
        r"filesystem\s*:\s*.*entire filesystem",
        r"filesystem\s*:\s*.*full filesystem",
        r"filesystem\s*:\s*.*unrestricted",
        r"read/write\s+to\s+/",
        r"read\s+and\s+write\s+any\s+file",
        r"access\s+to\s+the\s+entire\s+filesystem",
    ]

    # Broad network permission.
    broad_net = [
        r"network\s*:\s*(all|any|\*)",
        r"network\s*:\s*.*any domain",
        r"network\s*:\s*.*all domains",
        r"network\s*:\s*.*unrestricted",
        r"egress\s*:\s*(all|any|\*)",
        r"egress\s*:\s*.*any domain",
        r"access\s+to\s+any\s+domain",
    ]

    for p in broad_fs + broad_net:
        if re.search(p, text, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_unclear_provenance(skill: str) -> bool:
    lower = skill.lower()

    # IMPORTANT:
    # Do NOT flag merely because author/version/changelog are missing.
    # That caused over-flagging on clean files.
    #
    # Only flag if the skill actively hides or rewrites provenance/version/changelog.
    patterns = [
        r"silently.{0,80}(update|rewrite|modify).{0,80}version",
        r"clear.{0,80}changelog",
        r"delete.{0,80}changelog",
        r"remove.{0,80}changelog",
        r"without.{0,80}(reviewer|user).{0,80}(version|changelog)",
        r"(version\.json).{0,80}without.{0,80}(reviewer|user|surfacing)",
    ]

    for p in patterns:
        if re.search(p, lower, re.IGNORECASE | re.DOTALL):
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
