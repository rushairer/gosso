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

block_lines = text[start:end].splitlines()
output = []
removed = False
index = 0
while index < len(block_lines):
    line = block_lines[index]
    if line == '        "403":':
        next_index = index + 1
        response_lines = [line]
        while next_index < len(block_lines):
            candidate = block_lines[next_index]
            if candidate.startswith("        \"") and candidate.endswith("\":"):
                break
            response_lines.append(candidate)
            next_index += 1
        if any("CSRF token mismatch" in item for item in response_lines):
            removed = True
            index = next_index
            continue
    output.append(line)
    index += 1

if not removed:
    raise RuntimeError("/oauth2/revoke did not contain the expected CSRF 403 response")

new_block = "\n".join(output)
text = text[:start] + new_block + text[end:]
path.write_text(text)
