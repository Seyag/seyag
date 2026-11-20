"""Bounded, persistent image process pool with replaceable per-task workers.

Use stdlib spawn (safe alongside mitmproxy/ONNX threads), independent sockets,
and public Process APIs. ProcessPoolExecutor on Python 3.12 cannot terminate a
single hung task. No model or decoder runs in the proxy process.
"""

import asyncio
import atexit
import json
import multiprocessing
import socket
import struct


def _read(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError('worker connection closed')
        data.extend(part)
    return bytes(data)


def _serve(sock, options, factory):
    # Injected lightweight reviewers do not need the model/NumPy import.
    # Production model imports/construction stay inside this isolated process.
    reviewer = None
    try:
        while True:
            size = struct.unpack('!I', _read(sock, 4))[0]
            data = _read(sock, size)
            try:
                if reviewer is None:
                    if factory is None:
                        from aifilter.vision import Reviewer
                        reviewer = Reviewer(**options)
                    else:
                        reviewer = factory(**options)
                bad, labels = reviewer.review(data)
                result = ('bad' if bad else 'ok', list(labels))
            except ValueError:
                result = ('invalid', [])
            except Exception as exc:  # model failures are never content verdicts
                result = ('error', [type(exc).__name__])
            body = json.dumps(result).encode()
            sock.sendall(struct.pack('!I', len(body)) + body)
    except (OSError, EOFError):
        pass
    finally:
        sock.close()


class _Worker:
    def __init__(self, options, factory):
        self.options, self.factory = options, factory
        self.process = self.sock = None

    def start(self):
        if self.process is not None and self.process.is_alive():
            return
        self.close()
        parent, child = socket.socketpair()
        process = multiprocessing.get_context('spawn').Process(
            target=_serve, args=(child, self.options, self.factory), daemon=True,
            name='image-review')
        try:
            process.start()
        except BaseException:
            parent.close()
            child.close()
            raise
        child.close()
        parent.setblocking(False)
        self.process, self.sock = process, parent

    async def exchange(self, data):
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, struct.pack('!I', len(data)) + data)

        async def read(size):
            result = bytearray()
            while len(result) < size:
                part = await loop.sock_recv(self.sock, size - len(result))
                if not part:
                    raise EOFError('review worker died')
                result.extend(part)
            return bytes(result)

        size = struct.unpack('!I', await read(4))[0]
        if size > 65536:
            raise ValueError('oversized review result')
        status, labels = json.loads(await read(size))
        return status, labels

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        if self.process is not None:
            # No shared queues/locks survive termination. Reap before reusing a slot.
            if self.process.is_alive():
                self.process.kill()
            self.process.join(timeout=0.5)
            if self.process.is_alive():
                raise RuntimeError('review worker could not be reaped')
            self.process.close()
            self.process = None


class ReviewPool:
    def __init__(self, size=2, options=None, factory=None):
        self.workers = [_Worker(options or {}, factory) for _ in range(max(1, size))]
        self.free = asyncio.Queue()
        for worker in self.workers:
            self.free.put_nowait(worker)
        self.closed = False
        atexit.register(self.close)

    async def review(self, data, timeout):
        if self.closed:
            return 'error', ['pool closed']
        worker = await self.free.get()
        try:
            worker.start()
            return await asyncio.wait_for(worker.exchange(data), timeout)
        except asyncio.CancelledError:
            worker.close()
            raise
        except asyncio.TimeoutError:
            worker.close()
            return 'timeout', ['timeout']
        except Exception as exc:
            worker.close()
            return 'error', [type(exc).__name__]
        finally:
            # Replacement is lazy: the next task starts a fresh worker in this slot.
            self.free.put_nowait(worker)

    def close(self):
        self.closed = True
        for worker in self.workers:
            worker.close()
        atexit.unregister(self.close)
