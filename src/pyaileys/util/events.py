from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

Listener = Callable[..., Awaitable[None]] | Callable[..., None]


class AsyncEventEmitter:
    """
    Minimal async-friendly event emitter.

    - `on(event, fn)` registers a listener (sync or async).
    - `emit(event, *args, **kwargs)` awaits async listeners.
    - `wait_for(event, predicate, timeout)` waits for the next matching emission.
    """

    def __init__(self) -> None:
        self._listeners: dict[str, list[Listener]] = defaultdict(list)
        self._waiters: dict[str, list[tuple[Callable[..., bool] | None, asyncio.Future[Any]]]] = (
            defaultdict(list)
        )

    def wait_for_future(
        self, event: str, *, predicate: Callable[..., bool] | None = None
    ) -> asyncio.Future[Any]:
        """
        Register a waiter *synchronously* and return its Future.

        This avoids a common race where the event could be emitted between
        constructing an awaitable and actually awaiting it.
        """
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        self._waiters[event].append((predicate, fut))
        return fut

    def _remove_waiter_future(self, event: str, fut: asyncio.Future[Any]) -> None:
        waiters = self._waiters.get(event)
        if not waiters:
            return
        self._waiters[event] = [(p, f) for (p, f) in waiters if f is not fut and not f.done()]
        if not self._waiters[event]:
            self._waiters.pop(event, None)

    def on(self, event: str, listener: Listener) -> None:
        self._listeners[event].append(listener)

    def off(self, event: str, listener: Listener) -> None:
        listeners = self._listeners.get(event)
        if not listeners:
            return
        with contextlib.suppress(ValueError):
            listeners.remove(listener)

    def remove_all_listeners(self, event: str | None = None) -> None:
        if event is None:
            self._listeners.clear()
            self._waiters.clear()
            return
        self._listeners.pop(event, None)
        self._waiters.pop(event, None)

    async def emit(self, event: str, *args: Any, **kwargs: Any) -> bool:
        any_triggered = False

        waiters = self._waiters.get(event)
        if waiters:
            remaining: list[tuple[Callable[..., bool] | None, asyncio.Future[Any]]] = []
            for predicate, fut in waiters:
                if fut.done():
                    continue
                ok = True if predicate is None else bool(predicate(*args, **kwargs))
                if ok:
                    fut.set_result(args[0] if len(args) == 1 and not kwargs else (args, kwargs))
                    any_triggered = True
                else:
                    remaining.append((predicate, fut))
            if remaining:
                self._waiters[event] = remaining
            else:
                self._waiters.pop(event, None)

        for listener in list(self._listeners.get(event, [])):
            any_triggered = True
            res = listener(*args, **kwargs)
            if asyncio.iscoroutine(res):
                await res

        return any_triggered

    async def wait_for(
        self,
        event: str,
        *,
        predicate: Callable[..., bool] | None = None,
        timeout_s: float | None = None,
    ) -> Any:
        fut = self.wait_for_future(event, predicate=predicate)
        try:
            if timeout_s is None:
                return await fut
            return await asyncio.wait_for(fut, timeout=timeout_s)
        finally:
            # Remove the future if it's still pending (timeout/cancellation).
            self._remove_waiter_future(event, fut)
