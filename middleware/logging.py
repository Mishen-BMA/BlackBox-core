import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

from utils.logger import get_logger

logger = get_logger(__name__)


async def request_logging_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info("%s %s %s %.2fms", request.method, request.url.path, response.status_code, duration_ms)
    return response

