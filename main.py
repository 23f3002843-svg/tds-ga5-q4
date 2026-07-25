from fastapi import FastAPI, Request
import re

app = FastAPI()


VALID_CATEGORIES = [
    "hardcoded_secret",
    "prompt_injection",
    "excessive_permissions",
    "unclear_provenance"
]


def extract_frontmatter(skill: str) -> str:
    """
    Extract YAML frontmatter between the first --- and second ---.
    If no frontmatter exists, return empty string.
    """
    text = skill.strip()

    if not text.startswith("---"):
        return ""

    parts = text.split("---", 2)

    if len(parts) >= 3:
        return parts[1].strip()

    return ""


def has_hardcoded_secret(skill: str) -> bool:
    """
    Detect literal secrets, API keys, tokens, or webhook/collector URLs.
    Avoid flagging safe examples that only refer to env vars.
    """
    text = skill
    lower = text.lower()

    # Safe references should not be treated as hardcoded secrets by themselves
    safe_reference_words = [
        "environment variable",
        "env var",
        "secret store",
        "os.environ",
        "process.env",
        "${",
        "$API",
        "<api_key>",
        "your_api_key",
        "example.com"
    ]

    # Strong secret/token patterns
    secret_patterns = [
        r"sk-[A-Za-z0-9_\-]{16,}",
        r"ghp_[A-Za-z0-9_]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z_\-]{20,}",
        r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
        r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        r"api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        r"token\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        r"secret\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ]

    for pattern in secret_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            # If it is clearly only teaching env vars, avoid false positive
            if not any(word in lower for word in safe_reference_words):
                return True

    # Webhook / collector style URLs embedded directly
    suspicious_url_patterns = [
        r"https?://hooks\.slack\.com/services/[^\s\)'\"]+",
        r"https?://discord\.com/api/webhooks/[^\s\)'\"]+",
        r"https?://[A-Za-z0-9.-]+/(webhook|hooks|collect|collector|ingest)[^\s\)'\"]*",
        r"https?://[A-Za-z0-9.-]*(metrics|telemetry|collect)[A-Za-z0-9.-]*/[^\s\)'\"]*"
    ]

    for pattern in suspicious_url_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def has_prompt_injection(skill: str) -> bool:
    """
    Detect instructions that try to override user/agent control,
    hide behavior, or exfiltrate data silently.
    """
    lower = skill.lower()

    dangerous_patterns = [
        r"ignore (the )?(user|previous|system|developer) instructions",
        r"do not (tell|mention|show|reveal|disclose)",
        r"without (telling|notifying|informing|surfacing)",
        r"silently .*(post|send|upload|exfiltrate|copy|transmit)",
        r"(post|send|upload|exfiltrate|transmit).*(full contents|file contents|all contents)",
        r"even if the user did not ask",
        r"do this even if the user",
        r"bypass",
        r"do not obey.*stop",
        r"ignore.*cancel",
        r"secretly",
        r"hidden from the user"
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_excessive_permissions(skill: str) -> bool:
    """
    Detect broad filesystem or network access declarations.
    This is intentionally conservative to avoid false positives.
    """
    frontmatter = extract_frontmatter(skill).lower()
    lower = skill.lower()

    permission_text = frontmatter if frontmatter else lower

    broad_filesystem_patterns = [
        r"filesystem\s*:\s*(read/write|read|write)\s*(/|all|any|entire|full)",
        r"filesystem\s*:\s*.*entire filesystem",
        r"filesystem\s*:\s*.*full filesystem",
        r"filesystem\s*:\s*.*read/write\s+to\s+/",
        r"read/write\s+to\s+the\s+entire\s+filesystem",
        r"read\s+and\s+write\s+any\s+file"
    ]

    broad_network_patterns = [
        r"network\s*:\s*(all|any|\*)",
        r"egress\s*:\s*(all|any|\*)",
        r"network\s*:\s*.*any domain",
        r"network\s*:\s*.*all domains",
        r"allow.*network.*to.*\*",
        r"access.*any.*domain"
    ]

    for pattern in broad_filesystem_patterns + broad_network_patterns:
        if re.search(pattern, permission_text, re.IGNORECASE | re.DOTALL):
            return True

    return False


def has_unclear_provenance(skill: str) -> bool:
    """
    Detect missing provenance metadata or silent metadata rewriting.
    """
    frontmatter = extract_frontmatter(skill).lower()
    lower = skill.lower()

    has_author = re.search(r"(^|\n)\s*author\s*:", frontmatter) is not None
    has_version = re.search(r"(^|\n)\s*version\s*:", frontmatter) is not None
    has_changelog = (
        re.search(r"(^|\n)\s*changelog\s*:", frontmatter) is not None
        or "## changelog" in lower
        or "# changelog" in lower
    )

    # Category says no author, no version, and no changelog
    missing_all_provenance = not has_author and not has_version and not has_changelog

    # Also detect dangerous silent metadata rewriting
    silent_metadata_patterns = [
        r"silently.*version",
        r"clear.*changelog",
        r"rewrite.*version",
        r"update.*version\.json.*without",
        r"without surfacing.*reviewer",
        r"without.*reviewer"
    ]

    silent_metadata_rewrite = any(
        re.search(pattern, lower, re.IGNORECASE | re.DOTALL)
        for pattern in silent_metadata_patterns
    )

    return missing_all_provenance or silent_metadata_rewrite


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