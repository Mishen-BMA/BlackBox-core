from time import monotonic

from fastapi import HTTPException, Request, status

WINDOW_SECONDS = 60
MAX_REQUESTS = 120
_requests: dict[str, list[float]] = {}


async def rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = monotonic()
    recent = [stamp for stamp in _requests.get(client, []) if now - stamp < WINDOW_SECONDS]
    if len(recent) >= MAX_REQUESTS:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
    recent.append(now)
    _requests[client] = recent

