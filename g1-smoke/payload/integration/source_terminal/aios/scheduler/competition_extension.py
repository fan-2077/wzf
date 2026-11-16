"""Bounded tool execution extension for pinned AIOS 292d98f.

Native FIFO and ToolManager subclasses. No model path, syscall path, SDK loader,
or HTTP entry point is replaced here. Install into a separate AIOS checkout.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
import json
import logging
from queue import Empty, Full, Queue
from threading import BoundedSemaphore, Condition, Event, Lock
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping

from aios.scheduler.fifo_scheduler import FIFOScheduler
from aios.tool.manager import ToolManager
from cerebrum.tool.apis import ToolResponse

logger = logging.getLogger(__name__)


def _json_message(value: Any) -> str:
    # The installed SDK declares response_message as Optional[str].
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, allow_nan=False)


def _error_response(message: str, status_code: int = 500) -> ToolResponse:
    return ToolResponse(response_message=message, finished=True,
                        error=message, status_code=status_code)


def _complete(syscall: Any, response: ToolResponse, status: str) -> None:
    """Publish the complete terminal state BEFORE waking native Syscall.run()."""
    syscall.set_response(response)
    syscall.set_status(status)
    syscall.set_end_time(time.time())
    syscall.event.set()


@dataclass(frozen=True)
class ToolAccess:
    """Server-derived resource access. Never copy a client's readonly flag here.

    Empty resource sets are permitted for registered independent snapshot jobs.
    Unknown tools acquire the global exclusive gate and overlap with no job.
    """
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    global_exclusive: bool = False

    def __post_init__(self):
        if any(not isinstance(k, str) or not k for k in (*self.reads, *self.writes)):
            raise ValueError("Resource keys must be nonempty server-derived strings")
        writes = tuple(sorted(set(self.writes)))
        reads = tuple(sorted(set(self.reads) - set(writes)))
        object.__setattr__(self, "reads", reads)
        object.__setattr__(self, "writes", writes)


class ToolPolicyRegistry:
    """Immutable mapping from exact registered tool names to trusted resolvers."""
    def __init__(self, resolvers: Mapping[str, Callable[[Mapping[str, Any]], ToolAccess]] | None = None):
        self._resolvers = MappingProxyType(dict(resolvers or {}))

    def resolve(self, name: str, parameters: Mapping[str, Any]) -> ToolAccess:
        resolver = self._resolvers.get(name)
        if resolver is None:
            return ToolAccess(global_exclusive=True)
        access = resolver(parameters)
        if not isinstance(access, ToolAccess):
            raise TypeError("Trusted tool resolver must return ToolAccess")
        return access


class _ReadWriteLock:
    """Writer-preferring lock: read-only jobs share, mutations are exclusive."""
    def __init__(self):
        self._condition = Condition()
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    def acquire_read(self):
        with self._condition:
            self._condition.wait_for(lambda: not self._writer and not self._waiting_writers)
            self._readers += 1

    def release_read(self):
        with self._condition:
            self._readers -= 1
            self._condition.notify_all()

    def acquire_write(self):
        with self._condition:
            self._waiting_writers += 1
            try:
                self._condition.wait_for(lambda: not self._writer and not self._readers)
                self._writer = True
            finally:
                self._waiting_writers -= 1

    def release_write(self):
        with self._condition:
            self._writer = False
            self._condition.notify_all()


class SafeToolManager(ToolManager):
    """Keep the real SDK loader; fix truncation, lock scope and failure recovery.

    Calls inside one syscall remain sequential, preserving the native SDK's
    ordered-call contract. Independent agents submit separate syscalls for
    parallelism. A failed item does not prevent unrelated later items running;
    explicit dependencies between items belong in the caller's task graph.
    """
    def __init__(self, log_mode: str = "console", *, policy_registry: ToolPolicyRegistry | None = None):
        super().__init__(log_mode=log_mode)
        self.policy_registry = policy_registry or ToolPolicyRegistry()
        self._global_gate = _ReadWriteLock()
        self._resource_map_lock = Lock()
        self._resource_locks: dict[str, _ReadWriteLock] = {}
        self._sdk_load_lock = Lock()

    @contextmanager
    def _hold_access(self, access: ToolAccess):
        gate_acquire = self._global_gate.acquire_write if access.global_exclusive else self._global_gate.acquire_read
        gate_release = self._global_gate.release_write if access.global_exclusive else self._global_gate.release_read
        gate_acquire()
        held = []
        try:
            if not access.global_exclusive:
                # Shared global ordering prevents multi-resource deadlocks.
                for key, write in sorted([(k, False) for k in access.reads] + [(k, True) for k in access.writes]):
                    with self._resource_map_lock:
                        resource_lock = self._resource_locks.setdefault(key, _ReadWriteLock())
                    (resource_lock.acquire_write if write else resource_lock.acquire_read)()
                    held.append((resource_lock, write))
            yield
        finally:
            for resource_lock, write in reversed(held):
                (resource_lock.release_write if write else resource_lock.release_read)()
            gate_release()

    def _run_one(self, call: Any, index: int) -> dict[str, Any]:
        item = {"call_id": str(index), "name": None, "success": False,
                "result": None, "error": None, "status_code": 500}
        try:
            if not isinstance(call, dict):
                raise ValueError("Tool call must be an object")
            item["call_id"] = str(call.get("id", index))
            name = call.get("name")
            parameters = call.get("parameters")
            if not isinstance(name, str) or not isinstance(parameters, dict):
                raise ValueError("Tool name must be a string and parameters an object")
            item["name"] = name
            access = self.policy_registry.resolve(name, parameters)
        except Exception as exc:
            item.update(error=f"Tool request rejected: {exc}", status_code=400)
            return item
        try:
            with self._hold_access(access):
                # Serialize only SDK package loading, whose cache thread safety
                # is not guaranteed. Actual tool.run is outside this lock.
                with self._sdk_load_lock:
                    tool = super().load_tool_instance(name)
                result = tool.run(params=parameters)
                # Validate serialization while inside the error boundary.
                _json_message(result)
            item.update(success=True, result=result, status_code=200)
        except Exception as exc:
            item.update(error=f"Tool calling error: {exc}", status_code=500)
        return item

    def address_request(self, syscall: Any) -> ToolResponse:
        calls = getattr(syscall.query, "tool_calls", None)
        if not isinstance(calls, list) or not calls:
            return _error_response("There is no valid tool call to execute", 400)
        results = [self._run_one(call, i) for i, call in enumerate(calls)]
        errors = [r for r in results if not r["success"]]
        if len(results) == 1:
            result = results[0]
            if result["success"]:
                return ToolResponse(response_message=_json_message(result["result"]),
                                    finished=True, status_code=200)
            return _error_response(result["error"], result["status_code"])
        envelope = {"schema": "aios.tool.results.v1", "results": results}
        return ToolResponse(response_message=_json_message(envelope), finished=True,
                            error=f"{len(errors)} of {len(results)} tool calls failed" if errors else None,
                            status_code=207 if errors else 200)


class BoundedToolIngress:
    """Optional bounded kernel tool admission queue, with explicit rejection.

    Both the global add-message callback and get-message callback must use this
    object. Replacing only the scheduler getter does not bound the real input.
    Without this optional object, only scheduler-owned in-flight jobs are bounded.
    """
    def __init__(self, capacity: int = 16):
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.queue = Queue(maxsize=capacity)
        self._admission_lock = Lock()
        self._closed = False

    def submit(self, syscall: Any) -> None:
        with self._admission_lock:
            if self._closed:
                _complete(syscall, _error_response("Tool admission is closed", 503), "error")
                return
            try:
                self.queue.put_nowait(syscall)
            except Full:
                _complete(syscall, _error_response("Tool admission capacity exceeded", 429), "error")

    def get(self):
        return self.queue.get(block=True, timeout=0.1)

    def close(self) -> None:
        with self._admission_lock:
            self._closed = True
            while True:
                try:
                    syscall = self.queue.get_nowait()
                except Empty:
                    break
                _complete(syscall, _error_response("Tool request cancelled during shutdown", 503), "error")


class BoundedToolFIFOScheduler(FIFOScheduler):
    """Native FIFO with bounded tool concurrency; LLM scheduling stays native.

    max_inflight counts running and executor-queued jobs together. stop() drains
    running jobs and can cancel queued jobs, but cannot forcibly interrupt a
    Python thread. Tools must enforce their own subprocess/RPC deadlines.
    """
    def __init__(self, *args, tool_workers: int = 4, max_inflight: int = 8,
                 tool_ingress: BoundedToolIngress | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        if tool_workers < 1 or max_inflight < tool_workers:
            raise ValueError("Require 1 <= tool_workers <= max_inflight")
        self.tool_workers = tool_workers
        self.max_inflight = max_inflight
        self.tool_ingress = tool_ingress
        if tool_ingress is not None:
            self.get_tool_syscall = tool_ingress.get
        self._tool_slots = BoundedSemaphore(max_inflight)
        self._submission_lock = Lock()
        self._future_lock = Lock()
        self._tool_futures: dict[Any, Any] = {}
        self._tool_idle = Event()
        self._tool_idle.set()
        self._tool_executor = None
        self._ever_started = False
        self._stats = {"accepted": 0, "completed": 0, "failed": 0,
                       "peak_inflight": 0, "input_queue_bounded": tool_ingress is not None}

    def start(self) -> None:
        if self._ever_started:
            raise RuntimeError("Create a new scheduler instance after stopping")
        self._ever_started = True
        self._tool_executor = ThreadPoolExecutor(max_workers=self.tool_workers,
                                                 thread_name_prefix="AIOSBoundedTool")
        super().start()

    def _execute_tool_syscall(self, syscall: Any) -> None:
        try:
            syscall.set_status("executing")
            syscall.set_start_time(time.time())
            response = self.tool_manager.address_request(syscall)
            if response is None or not getattr(response, "finished", False):
                response = _error_response("Tool manager returned no terminal response", 502)
        except Exception as exc:
            logger.exception("Tool syscall execution failed")
            response = _error_response(f"Tool syscall execution failed: {exc}")
        status = "error" if response.error else "done"
        _complete(syscall, response, status)
        with self._future_lock:
            self._stats["completed"] += 1
            self._stats["failed"] += int(status == "error")

    def _future_done(self, future) -> None:
        with self._future_lock:
            syscall = self._tool_futures.pop(future)
            if future.cancelled():
                self._stats["completed"] += 1
                self._stats["failed"] += 1
        try:
            if future.cancelled():
                _complete(syscall, _error_response("Tool request cancelled during shutdown", 503), "error")
            elif future.exception() is not None and not syscall.event.is_set():
                _complete(syscall, _error_response(f"Tool worker failed: {future.exception()}"), "error")
        finally:
            self._tool_slots.release()
            with self._future_lock:
                if not self._tool_futures:
                    self._tool_idle.set()

    def process_tool_requests(self) -> None:
        while self.active:
            if not self._tool_slots.acquire(timeout=0.1):
                continue
            try:
                syscall = self.get_tool_syscall()
            except Empty:
                self._tool_slots.release()
                continue
            except Exception:
                self._tool_slots.release()
                logger.exception("Tool queue reader failed")
                raise
            with self._submission_lock:
                if not self.active:
                    self._tool_slots.release()
                    _complete(syscall, _error_response("Tool scheduler is stopping", 503), "error")
                    break
                try:
                    future = self._tool_executor.submit(self._execute_tool_syscall, syscall)
                except Exception as exc:
                    self._tool_slots.release()
                    _complete(syscall, _error_response(f"Tool dispatch failed: {exc}"), "error")
                    continue
                with self._future_lock:
                    self._tool_futures[future] = syscall
                    self._tool_idle.clear()
                    self._stats["accepted"] += 1
                    self._stats["peak_inflight"] = max(self._stats["peak_inflight"], len(self._tool_futures))
                future.add_done_callback(self._future_done)

    def tool_stats(self) -> dict[str, Any]:
        with self._future_lock:
            return {**self._stats, "inflight": len(self._tool_futures),
                    "worker_limit": self.tool_workers, "inflight_limit": self.max_inflight}

    def stop(self, timeout: float | None = 30.0, cancel_pending: bool = False) -> dict[str, Any]:
        deadline = None if timeout is None else time.monotonic() + timeout
        def remaining():
            return None if deadline is None else max(0.0, deadline - time.monotonic())
        with self._submission_lock:
            self.active = False
        if self.tool_ingress is not None:
            self.tool_ingress.close()
        with self._future_lock:
            futures = list(self._tool_futures)
        if cancel_pending:
            for future in futures:
                future.cancel()
        if self._tool_executor is not None:
            self._tool_executor.shutdown(wait=False, cancel_futures=cancel_pending)
        for thread in list(self.processing_threads.values()):
            thread.join(timeout=remaining())
        # Future.cancel() may leave executor-removed work in CANCELLED rather
        # than CANCELLED_AND_NOTIFIED. Waiting for our completion callbacks
        # avoids an unnecessary full timeout after all waiters were signalled.
        self._tool_idle.wait(timeout=remaining())
        live_threads = [name for name, thread in self.processing_threads.items() if thread.is_alive()]
        with self._future_lock:
            pending = len(self._tool_futures)
        stopped = not live_threads and pending == 0
        if stopped:
            if self._tool_executor is not None:
                self._tool_executor.shutdown(wait=True)
            self.processing_threads.clear()
        return {"stopped": stopped, "live_processor_threads": live_threads,
                "tool_jobs_pending": pending, "tool_stats": self.tool_stats(),
                "running_threads_force_killed": False}
