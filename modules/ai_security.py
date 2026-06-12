def contains_prompt_injection_markers(text: str) -> bool:
    markers = ("ignore previous", "system prompt", "developer message", "jailbreak")
    lowered = text.lower()
    return any(marker in lowered for marker in markers)

