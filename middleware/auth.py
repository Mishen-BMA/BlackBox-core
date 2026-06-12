from fastapi import HTTPException, Request, status

from config.settings import settings


async def require_api_key(request: Request) -> None:
    if not settings.API_KEY:
        return
    if request.headers.get("x-api-key") != settings.API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

