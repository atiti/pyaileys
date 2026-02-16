from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


async def promise_timeout(timeout_s: float, coro: Awaitable[T]) -> T:
    return await asyncio.wait_for(coro, timeout=timeout_s)


async def cancel_suppress(task: asyncio.Task[object] | None) -> None:
    if not task:
        return
    # Never cancel/await the current task: doing so can deadlock or raise
    # "Task cannot await on itself". Callers typically set a stop flag and then
    # return from the current task naturally.
    if task is asyncio.current_task():
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def ensure_task(coro: Coroutine[Any, Any, T], *, name: str | None = None) -> asyncio.Task[T]:
    t: asyncio.Task[T] = asyncio.create_task(coro)
    if name:
        with contextlib.suppress(Exception):
            t.set_name(name)
    return t


def shielded(cb: Callable[..., Awaitable[object]]) -> Callable[..., Coroutine[Any, Any, None]]:
    async def _wrapped(*args: object, **kwargs: object) -> None:
        try:
            await cb(*args, **kwargs)
        except Exception:
            # Event listeners should not tear down the receive loop by default.
            return

    return _wrapped
