"""Bounded hook wall-time samples: no file I/O on the mitmproxy event loop."""
import functools
import inspect
import time


def timed(method):
    if inspect.iscoroutinefunction(method):
        @functools.wraps(method)
        async def async_hook(self, *args, **kwargs):
            start = time.perf_counter()
            try:
                return await method(self, *args, **kwargs)
            finally:
                self.latency.add(method.__name__, time.perf_counter() - start)
        return async_hook

    @functools.wraps(method)
    def hook(self, *args, **kwargs):
        start = time.perf_counter()
        try:
            return method(self, *args, **kwargs)
        finally:
            self.latency.add(method.__name__, time.perf_counter() - start)
    return hook
