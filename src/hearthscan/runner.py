"""Run a coroutine so that Ctrl+C cancels it instead of tearing through the loop."""

from __future__ import annotations

import asyncio
import signal
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")


def run(main: Coroutine[Any, Any, T]) -> T:
    """Like asyncio.run, but Ctrl+C cancels `main` and raises KeyboardInterrupt here.

    With the default handler KeyboardInterrupt goes off wherever the loop
    happens to be. On Windows that can leave the proactor spinning forever on
    close, or fail with InvalidStateError.
    """
    loop = asyncio.new_event_loop()
    task = loop.create_task(main)
    previous = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGINT, lambda *_: loop.call_soon_threadsafe(task.cancel))
    try:
        return loop.run_until_complete(task)
    except asyncio.CancelledError:
        raise KeyboardInterrupt from None
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
        try:
            _cancel_leftovers(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()


def _cancel_leftovers(loop: asyncio.AbstractEventLoop) -> None:
    leftovers = [t for t in asyncio.all_tasks(loop) if not t.done()]
    for t in leftovers:
        t.cancel()
    if leftovers:
        loop.run_until_complete(asyncio.gather(*leftovers, return_exceptions=True))
