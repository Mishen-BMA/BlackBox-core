from functools import wraps
from time import monotonic
from typing import Any, Callable


def timed(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = monotonic()
        result = func(*args, **kwargs)
        wrapper.last_duration = monotonic() - start
        return result

    wrapper.last_duration = 0.0
    return wrapper

