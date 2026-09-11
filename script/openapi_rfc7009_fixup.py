from pathlib import Path

path = Path("docs/openapi.yaml")
text = path.read_text()

# Keep the API document release marker aligned with the patch release.
text = text.replace("  version: 1.5.8\n", "  version: 1.6.1\n", 1)

start = text.index("  /oauth2/revoke:\n")
try:
    end = text.index("\n  /oauth2/introspect:\n", start)
except ValueError:
    end = text.index("\n  /oauth2/device", start)
block = text[start:end]

old_description = "      description: Revokes a refresh token. Requires authentication.\n"
new_description = (
    "      description: |\n"
    "        Revokes an access or refresh token. Confidential clients authenticate at the\n"
    "        OAuth protocol layer with `client_secret_basic` (preferred) or client credentials\n"
    "        in the form body. A valid client receives HTTP 200 even when the token is already\n"
    "        invalid or unknown, preserving RFC 7009 token-status non-disclosure.\n"
)
if old_description in block:
    block = block.replace(old_description, new_description, 1)

old_security = "      security:\n        - BearerAuth: []\n"
new_security = "      security:\n        - BasicAuth: []\n"
if old_security not in block:
    raise RuntimeError("/oauth2/revoke BearerAuth contract was not found")
block = block.replace(old_security, new_security, 1)

# Older generated documentation may still list a browser-CSRF 403 response for
# this protocol endpoint. Remove it if present, but do not require it to exist.
lines = block.splitlines()
output = []
index = 0
while index < len(lines):
    line = lines[index]
    if line == '        "403":':
        next_index = index + 1
        response_lines = [line]
        while next_index < len(lines):
            candidate = lines[next_index]
            if candidate.startswith("        \"") and candidate.endswith("\":"):
                break
            response_lines.append(candidate)
            next_index += 1
        if any("CSRF token mismatch" in item for item in response_lines):
            index = next_index
            continue
    output.append(line)
    index += 1

new_block = "\n".join(output)
text = text[:start] + new_block + text[end:]
path.write_text(text)
