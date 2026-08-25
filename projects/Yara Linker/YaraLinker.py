import re

def parse_yara_output(text: str):
    """
    Parses yara -s style output into a list of matches:
    [
        {
            "rule": "version_arm7",
            "file": "C:\\...\\5bee485e...",
            "strings": {
                "$Config": {
                    "address": 0x308a74,
                    "bytes": b"\x44\x02\x9F..."
                }
            }
        },
        ...
    ]
    """
    matches = []
    current = None

    # matches a header line: "rule_name  file_path"
    header_re = re.compile(r"^(\S+)\s+(.+)$")
    # matches a string line: "0x308a74:$Config: 44 02 9F E5 ..."
    string_re = re.compile(r"^0x([0-9a-fA-F]+):(\$\S+):\s*([0-9A-Fa-f ]+)$")

    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        m = string_re.match(line)
        if m:
            addr = int(m.group(1), 16)
            string_id = m.group(2)
            hex_bytes = m.group(3).strip().split()
            raw = bytes(int(b, 16) for b in hex_bytes)

            current["strings"][string_id] = {
                "address": addr,
                "bytes": raw
            }
            continue

        h = header_re.match(line)
        if h:
            rule_name, file_path = h.group(1), h.group(2)
            current = {"rule": rule_name, "file": file_path, "strings": {}}
            matches.append(current)

    return matches