SAFE_COMMANDS: set[str] = {
    "file",
    "strings",
    "exiftool",
    "binwalk",
    "zsteg",
    "steghide",
    "hashcat",
    "john",
    "nmap",
    "dig",
    "whois",
}


def is_allowed_tool(command: str) -> bool:
    return command.split()[0] in SAFE_COMMANDS if command.strip() else False

