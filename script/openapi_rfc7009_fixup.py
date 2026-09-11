from pathlib import Path
import re

path = Path("docs/openapi.yaml")
text = path.read_text()

# Keep the document version aligned with the patch release prepared by this PR.
text = text.replace("  version: 1.5.8\n", "  version: 1.6.1\n", 1)

start = text.index("  /oauth2/revoke:\n")
try:
    end = text.index("\n  /oauth2/introspect:\n", start)
except ValueError:
    end = text.index("\n  /oauth2/device", start)
block = text[start:end]

pattern = re.compile(
    r'\n        "403":\n'
    r'          description: CSRF token mismatch\n'
    r'          content:\n'
    r'            application/json:\n'
    r'              schema:\n'
    r'                \$ref: "#/components/schemas/OAuth2Error"\n'
)
block, count = pattern.subn("\n", block, count=1)
if count != 1:
    raise RuntimeError("expected RFC 7009 CSRF 403 response was not found exactly once")

text = text[:start] + block + text[end:]
path.write_text(text)
