"""Optional bounded, continuously admitted LLM syscalls for the pinned AIOS.

Keeps the native LLMAdapter, model routing, SDK and model service. Each worker
passes one native syscall to execute_llm_syscalls; the local inference server
can add that request to its active batch without waiting for an earlier kernel
batch to finish. This is admission concurrency, not a claim of faster hardware.
The tested deployment has one local model and disabled context interruption.
"""
from concurrent.futures import ThreadPoolExecutor
from queue import Empty
from threading import BoundedSemaphore, Event, Lock
import logging
import time

from aios.scheduler.competition_extension import BoundedToolFIFOScheduler
from cerebrum.llm.apis import LLMResponse

logger = logging.getLogger(__name__)


def terminal_error(syscall, message, status_code=500):
    if syscall.event.is_set():
        return
    syscall.set_response(LLMResponse(response_message=None, error=message,
                                    finished=True, status_code=status_code))
    syscall.set_status('error')
    syscall.set_end_time(time.time())
    syscall.event.set()


class BoundedConcurrentScheduler(BoundedToolFIFOScheduler):
    """Bound native model admission as well as the inherited tool execution.

    Existing global input queues are not claimed to be bounded. At most
    llm_max_inflight requests are owned by this executor; the default of four
    equals the local server's four slots. No response or prompt is replayed.
    Running Python/API calls require their own deadlines and cannot be killed
    safely by this scheduler's stop method.
    """
    def __init__(self, *args, llm_workers=4, llm_max_inflight=4, **kwargs):
        super().__init__(*args, **kwargs)
        if not 1 <= llm_workers <= llm_max_inflight:
            raise ValueError('Require 1 <= llm_workers <= llm_max_inflight')
        self.llm_workers = llm_workers
        self.llm_max_inflight = llm_max_inflight
        self._llm_slots = BoundedSemaphore(llm_max_inflight)
        self._llm_submission = Lock()
        self._llm_state = Lock()
        self._llm_futures = {}
        self._llm_idle = Event()
        self._llm_idle.set()
        self._llm_executor = None
        self._llm_stats = {'accepted': 0, 'completed': 0, 'failed': 0,
                           'peak_inflight': 0, 'input_queue_bounded': False}

    def start(self):
        if self._ever_started:
            raise RuntimeError('Create a new scheduler instance after stopping')
        self._llm_executor = ThreadPoolExecutor(max_workers=self.llm_workers,
                                                thread_name_prefix='AIOSBoundedLLM')
        super().start()

    def _run_llm(self, syscall):
        logger.info('Continuous LLM start: %s', syscall.agent_name)
        try:
            syscall.set_status('executing')
            syscall.set_start_time(time.time())
            self.llm.execute_llm_syscalls([syscall])
            if not syscall.event.is_set():
                terminal_error(syscall, 'Native model adapter returned without a terminal notification', 502)
        except Exception as exc:
            logger.exception('Native model syscall failed')
            terminal_error(syscall, 'Native model syscall failed: ' + str(exc))
        finally:
            logger.info('Continuous LLM terminal: %s status=%s', syscall.agent_name, syscall.status)

    def _llm_done(self, future):
        with self._llm_state:
            syscall = self._llm_futures.pop(future)
        try:
            if future.cancelled():
                terminal_error(syscall, 'Model request cancelled during shutdown', 503)
            elif future.exception() is not None:
                terminal_error(syscall, 'Model worker failed: ' + str(future.exception()))
            with self._llm_state:
                self._llm_stats['completed'] += 1
                self._llm_stats['failed'] += int(getattr(syscall.response, 'error', None) is not None)
        finally:
            self._llm_slots.release()
            with self._llm_state:
                if not self._llm_futures:
                    self._llm_idle.set()

    def process_llm_requests(self):
        while self.active:
            if not self._llm_slots.acquire(timeout=0.1):
                continue
            try:
                syscall = self.get_llm_syscall()
            except Empty:
                self._llm_slots.release()
                continue
            except Exception:
                self._llm_slots.release()
                logger.exception('Model queue reader failed')
                raise
            with self._llm_submission:
                if not self.active:
                    self._llm_slots.release()
                    terminal_error(syscall, 'Model scheduler is stopping', 503)
                    break
                try:
                    future = self._llm_executor.submit(self._run_llm, syscall)
                except Exception as exc:
                    self._llm_slots.release()
                    terminal_error(syscall, 'Model dispatch failed: ' + str(exc))
                    continue
                with self._llm_state:
                    self._llm_futures[future] = syscall
                    self._llm_idle.clear()
                    self._llm_stats['accepted'] += 1
                    self._llm_stats['peak_inflight'] = max(self._llm_stats['peak_inflight'], len(self._llm_futures))
                future.add_done_callback(self._llm_done)

    def llm_stats(self):
        with self._llm_state:
            return {**self._llm_stats, 'inflight': len(self._llm_futures),
                    'worker_limit': self.llm_workers, 'inflight_limit': self.llm_max_inflight}

    def stop(self, timeout=30.0, cancel_pending=False):
        deadline = None if timeout is None else time.monotonic() + timeout
        def remaining():
            return None if deadline is None else max(0.0, deadline - time.monotonic())
        with self._llm_submission:
            self.active = False
        with self._llm_state:
            futures = list(self._llm_futures)
        if cancel_pending:
            for future in futures:
                future.cancel()
        if self._llm_executor is not None:
            self._llm_executor.shutdown(wait=False, cancel_futures=cancel_pending)
        result = super().stop(timeout=remaining(), cancel_pending=cancel_pending)
        # No dispatcher will dequeue after the active flag was cleared. Notify
        # requests already waiting in the native input queue as well. The HTTP
        # ingress must be closed separately before shutdown; this does not make
        # the native global queue a bounded/closed admission endpoint.
        drained = 0
        while True:
            try:
                syscall = self.get_llm_syscall()
            except Empty:
                break
            terminal_error(syscall, 'Queued model request cancelled during shutdown', 503)
            drained += 1
        self._llm_idle.wait(remaining())
        stats = self.llm_stats()
        result.update(llm_stats=stats, llm_jobs_pending=stats['inflight'],
                      llm_input_queue_cancelled=drained)
        result['stopped'] = result['stopped'] and stats['inflight'] == 0
        if stats['inflight'] == 0 and self._llm_executor is not None:
            self._llm_executor.shutdown(wait=True)
        return result
