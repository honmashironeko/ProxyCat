"""
模块名称：modules.proxy_workers
功能描述：上游出口代理池：在多个出口之间分配请求（默认按负载最少，亦可按名册顺序），
          给每个出口套独立的并发额度与活跃窗口，并用失败滑窗把持续失败的出口移出名册。
职责边界：负责：worker 名册增删替换、出口挑选、名额等待与归还、活跃窗口结算、失败滑窗与
          停用判定、候补队列与展示快照；不负责：代理的获取与可用性验证（见 config.getip、
          modules.proxypool_service）以及请求转发与重试（见 modules.proxyserver）。
关键依赖：modules.access_log 的 sanitize_proxy；标准库 asyncio、threading、time、collections。
已知限制：
1. 名额绑定在连接任务上：asyncio.gather 包装出的子任务里 asyncio.current_task() 查不到租约，worker/lease 必须由调用方显式传下去。
2. 活跃窗口靠 expire_idle 惰性结算，没有独立定时器；wake=True 只能在事件循环线程用，调用方不周期性触发则活跃数不会回落。
3. 额度等待不设超时，每 _QUEUE_RECHECK_SECONDS 自行重查一次；放行凭据按腾出的名额逐张发放，一次释放只唤起一个等待者。
4. 活跃口径的额度是准入控制而非运行时硬上限：空闲隧道不占额度，数据到达重新计入时计数可能超过 capacity。
5. 停用只把 worker 移出名册，不关闭它已建立的连接；名册里最后一个出口永不被停用。
6. 寿命的 expires_at 与 requests_served 两条口径同时生效、谁先到算谁；requests_served 记分配次数而非服务成功次数，0 表示不按该项计。
7. rebind 必须先给旧租约置 _released 再清空租约表；否则清表后一次迟到的 touch 会把已归零的 active 永久加 1。
"""

import asyncio
import threading
import time
from collections import deque

from modules.access_log import sanitize_proxy

DEFAULT_CAPACITY = 0

BLAME_IGNORED = 'ignored'
BLAME_COUNTED = 'counted'
BLAME_RETIRED = 'retired'

_OUTCOME_WINDOW = 10

_SUSPECT_FAILURE_RATIO = 0.5

_RETIRE_MIN_OUTCOMES = 5
_RETIRE_FAILURE_RATIO = 0.9

RETIRED_MEMORY_SECONDS = 300.0

ACTIVITY_WINDOW_SECONDS = 5.0

_QUEUE_RECHECK_SECONDS = 0.5

STANDBY_TTL_SECONDS = 30.0

STANDBY_LIMIT = 200


class ProxyWorker:
    __slots__ = ('url', 'masked', 'capacity', 'inflight', 'active', 'failures',
                 'outcomes', 'last_used', 'added_at', 'retired',
                 'expires_at', 'requests_served')

    def __init__(self, url, masked, capacity, expires_at=0.0):
        self.url = url
        self.masked = masked
        self.capacity = capacity
        self.inflight = 0
        self.active = 0
        self.failures = 0
        self.outcomes = deque(maxlen=_OUTCOME_WINDOW)
        self.last_used = 0.0
        self.added_at = time.monotonic()
        self.expires_at = expires_at
        self.requests_served = 0
        self.retired = False

    @property
    def failure_ratio(self):
        if not self.outcomes:
            return 0.0
        return sum(1 for ok in self.outcomes if not ok) / len(self.outcomes)

    @property
    def suspect(self):
        return self.failure_ratio > _SUSPECT_FAILURE_RATIO

    def has_free_slot(self):
        return not self.capacity or self.active < self.capacity

    @property
    def load(self):
        if self.capacity:
            return self.active / self.capacity
        return float(self.active)

    def snapshot(self):
        return {
            'url': self.masked,
            'inflight': self.inflight,
            'active': self.active,
            'capacity': self.capacity,
            'failures': self.failures,
            'suspect': self.suspect,
            'failure_ratio': round(self.failure_ratio, 3),
            'last_used': self.last_used,
            'added_at': self.added_at,
            'expires_at': self.expires_at,
            'requests_served': self.requests_served,
        }


class StandbyQueue:
    def __init__(self, ttl=STANDBY_TTL_SECONDS, limit=STANDBY_LIMIT):
        self._entries = []
        self._ttl = ttl
        self._limit = limit

    def put(self, urls):
        self._expire()
        known = {url for url, _expires in self._entries}
        added = 0
        for url in urls:
            if url in known:
                continue
            known.add(url)
            self._entries.append((url, time.monotonic() + self._ttl))
            added += 1
        if len(self._entries) > self._limit:
            del self._entries[:len(self._entries) - self._limit]
        return added

    def take(self):
        self._expire()
        if not self._entries:
            return None
        url, _expires = self._entries.pop(0)
        return url

    def clear(self):
        self._entries.clear()

    def __len__(self):
        self._expire()
        return len(self._entries)

    def _expire(self):
        now = time.monotonic()
        self._entries = [entry for entry in self._entries if entry[1] > now]


class WorkerLease:
    __slots__ = ('worker', '_pool', '_key', '_released', 'busy',
                 '_counted', '_active_until')

    def __init__(self, worker, pool, key, active_until=0.0):
        self.worker = worker
        self._pool = pool
        self._key = key
        self._released = False
        self.busy = True
        self._counted = True
        self._active_until = active_until

    @property
    def url(self):
        return self.worker.url

    def idle(self):
        self._pool.mark_idle(self)

    def touch(self):
        self._pool.touch(self)


class ProxyWorkerPool:
    def __init__(self, capacity=DEFAULT_CAPACITY, activity_window=ACTIVITY_WINDOW_SECONDS):
        self._capacity = max(0, int(capacity or 0))
        self._activity_window = max(0.0, float(activity_window))
        self._workers = ()
        self._leases = {}
        self._watched = set()
        self._retired_at = {}
        self._cursor = 0
        self._selection = 'load'
        self._revision = 0
        self._next_expiry = float('inf')
        self._lock = threading.Lock()
        self._wakeup = asyncio.Event()
        self._quota = asyncio.Semaphore(0)
        self._waiting = 0
        self._generation = 0
        self._event_loop = None

    def rebind(self):
        loop = asyncio.get_running_loop()
        with self._lock:
            self._wakeup = asyncio.Event()
            self._quota = asyncio.Semaphore(0)
            self._waiting = 0
            self._generation += 1
            self._event_loop = loop
            for lease in self._leases.values():
                lease._released = True
            self._leases.clear()
            self._watched.clear()
            self._revision += 1
            self._next_expiry = float('inf')
            for worker in self._workers:
                worker.inflight = 0
                worker.active = 0

    def _signal_wakeup(self, permits=None):
        loop = self._event_loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._wakeup.set)
            if permits is None or permits > 0:
                loop.call_soon_threadsafe(self._wake_up_waiters, permits)
        except RuntimeError:
            pass

    def _wake_up_waiters(self, permits=None) -> None:
        with self._lock:
            pending = self._waiting
        count = pending if permits is None else min(permits, pending)
        for _ in range(max(0, count)):
            self._quota.release()

    def set_selection(self, selection):
        self._selection = 'order' if selection == 'order' else 'load'

    def apply_capacity(self, capacity):
        with self._lock:
            self._capacity = max(0, int(capacity or 0))
            for worker in self._workers:
                worker.capacity = self._capacity

    def set_workers(self, urls):
        with self._lock:
            survivors = {worker.url: worker for worker in self._workers}
            workers = []
            for url in urls:
                worker = survivors.pop(url, None)
                if worker is None:
                    worker = ProxyWorker(url, sanitize_proxy(url), self._capacity)
                else:
                    worker.capacity = self._capacity
                workers.append(worker)
            for orphan in survivors.values():
                orphan.retired = True
            self._workers = tuple(workers)
            self._revision += 1
        self._signal_wakeup()

    def add_worker(self, url, expires_at=0.0):
        with self._lock:
            existing = self.find(url)
            if existing is not None:
                return existing
            worker = ProxyWorker(url, sanitize_proxy(url), self._capacity, expires_at)
            self._workers = self._workers + (worker,)
            self._revision += 1
        self._signal_wakeup(self._capacity)
        return worker

    @staticmethod
    def lifetime_ended(worker, now, request_limit=0) -> bool:
        if worker.expires_at and now >= worker.expires_at:
            return True
        return request_limit > 0 and worker.requests_served >= request_limit

    def expired_workers(self, now, request_limit=0):
        return [w for w in self._workers
                if self.lifetime_ended(w, now, request_limit)]

    def replan_expiries(self, expires_at):
        with self._lock:
            for worker in self._workers:
                worker.expires_at = expires_at

    async def wait_for_roster_change(self, timeout):
        with self._lock:
            self._wakeup.clear()
        try:
            await asyncio.wait_for(self._wakeup.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    def readmit(self, worker, expires_at) -> bool:
        with self._lock:
            if worker.retired or worker not in self._workers:
                return False
            worker.expires_at = expires_at
            worker.requests_served = 0
            worker.added_at = time.monotonic()
            return True

    def drop_worker(self, url, remember=False):
        with self._lock:
            worker = self.find(url)
            if worker is None:
                return False
            worker.retired = True
            self._workers = tuple(w for w in self._workers if w is not worker)
            if remember:
                self._retired_at[worker.url] = time.monotonic()
                self._prune_retired_locked()
            self._revision += 1
        self._signal_wakeup(0)
        return True

    def _prune_retired_locked(self):
        now = time.monotonic()
        expired = [url for url, at in self._retired_at.items()
                   if now - at >= RETIRED_MEMORY_SECONDS]
        for url in expired:
            self._retired_at.pop(url, None)

    @property
    def roster(self):
        return self._workers

    def find(self, url):
        for worker in self._workers:
            if worker.url == url:
                return worker
        return None

    def recently_retired(self, url, within=RETIRED_MEMORY_SECONDS):
        retired_at = self._retired_at.get(url)
        return retired_at is not None and (time.monotonic() - retired_at) < within

    def snapshot(self):
        self.expire_idle(wake=False)
        return [worker.snapshot() for worker in self._workers]

    def lease_of(self, task):
        with self._lock:
            return self._leases.get(task)

    def saturation(self, reference_capacity):
        if not reference_capacity:
            return None

        with self._lock:
            workers = [w for w in self._workers if not w.retired]
            if not workers:
                return None
            return sum(1 for w in workers if w.active >= reference_capacity) / len(workers)

    def utilization(self, reference_capacity):
        if not reference_capacity:
            return None

        with self._lock:
            workers = [w for w in self._workers if not w.retired]
            if not workers:
                return None
            used = sum(min(w.active, reference_capacity) for w in workers)
            return used / (len(workers) * reference_capacity)

    def _pick(self, exclude=None):
        roster = self._workers
        if not roster:
            return None

        capable = [w for w in roster if w.has_free_slot()]
        if exclude is not None and capable:
            without = [w for w in capable if w.url != exclude]
            if without:
                capable = without
        if not capable:
            return None

        healthy = [worker for worker in capable if not worker.suspect]
        pool = healthy or capable

        if self._selection == 'order':
            return pool[0]

        best_load = min(worker.load for worker in pool)
        top = [worker for worker in pool if worker.load == best_load]
        if len(top) == 1:
            return top[0]

        index_of = {id(worker): index for index, worker in enumerate(roster)}
        chosen = min(top, key=lambda w: (index_of[id(w)] - self._cursor) % len(roster))
        self._cursor = (index_of[id(chosen)] + 1) % len(roster)
        return chosen

    async def acquire(self, task=None, exclude=None):
        key = task if task is not None else asyncio.current_task()
        if key is None:
            key = object()

        self.release(key)

        while True:
            with self._lock:
                self._expire_locked(time.monotonic())
                worker = self._pick(exclude)
                if worker is not None:
                    now = time.monotonic()
                    worker.inflight += 1
                    worker.active += 1
                    worker.requests_served += 1
                    worker.last_used = now
                    lease = WorkerLease(worker, self, key, now + self._activity_window)
                    self._leases[key] = lease
                    self._watch(key)
                    return lease
                if not self._workers:
                    return None
                self._waiting += 1
                generation = self._generation
            try:
                await asyncio.wait_for(self._quota.acquire(), _QUEUE_RECHECK_SECONDS)
            except asyncio.TimeoutError:
                pass
            finally:
                with self._lock:
                    if generation == self._generation:
                        self._waiting -= 1

    def _watch(self, key):
        if key in self._watched:
            return
        add_done_callback = getattr(key, 'add_done_callback', None)
        if add_done_callback is None:
            return
        self._watched.add(key)
        add_done_callback(self._on_task_done)

    def _on_task_done(self, task):
        self._watched.discard(task)
        self.release(task)

    def release(self, task, blame=False, reason=''):
        with self._lock:
            lease = self._leases.pop(task, None)
            if lease is None:
                return None
            lease._released = True
            worker = lease.worker
            worker.inflight = max(0, worker.inflight - 1)
            freed_slot = lease._counted
            if lease._counted:
                lease._counted = False
                worker.active = max(0, worker.active - 1)
            outcome = self._blame_locked(worker, reason) if blame else None
            if freed_slot or outcome == BLAME_RETIRED:
                self._wakeup.set()
            permits = 1 if freed_slot else 0
        for _ in range(permits):
            self._quota.release()
        return outcome

    def mark_idle(self, lease):
        with self._lock:
            if lease._released:
                return
            lease.busy = False
            if lease._counted:
                self._note_expiry_locked(lease)

    def touch(self, lease):
        with self._lock:
            if lease._released:
                return
            lease._active_until = time.monotonic() + self._activity_window
            if not lease._counted:
                lease._counted = True
                lease.worker.active += 1
            if not lease.busy:
                self._note_expiry_locked(lease)

    def expire_idle(self, now=None, wake=False) -> int:
        with self._lock:
            expired = self._expire_locked(time.monotonic() if now is None else now)
            if expired and wake:
                self._wakeup.set()
                permits = min(expired, self._waiting)
            else:
                permits = 0
        for _ in range(permits):
            self._quota.release()
        return expired

    def _expire_locked(self, now) -> int:
        if now < self._next_expiry:
            return 0
        expired = 0
        soonest = float('inf')
        for lease in self._leases.values():
            if not lease._counted or lease.busy:
                continue
            if lease._active_until <= now:
                lease._counted = False
                lease.worker.active = max(0, lease.worker.active - 1)
                expired += 1
                continue
            if lease._active_until < soonest:
                soonest = lease._active_until
        self._next_expiry = soonest
        return expired

    def _note_expiry_locked(self, lease) -> None:
        if lease._active_until < self._next_expiry:
            self._next_expiry = lease._active_until

    def _blame_locked(self, worker, reason):
        if worker.retired:
            return BLAME_IGNORED

        worker.failures += 1
        worker.outcomes.append(False)
        if not self._should_retire(worker):
            return BLAME_COUNTED

        if len(self._workers) <= 1:
            return BLAME_COUNTED

        self._retire_locked(worker)
        return BLAME_RETIRED

    @staticmethod
    def _should_retire(worker) -> bool:
        outcomes = worker.outcomes
        if len(outcomes) < _RETIRE_MIN_OUTCOMES:
            return False
        return worker.failure_ratio >= _RETIRE_FAILURE_RATIO

    def _retire_locked(self, worker):
        self._retired_at[worker.url] = time.monotonic()
        worker.retired = True
        self._workers = tuple(w for w in self._workers if w is not worker)
        self._revision += 1
        self._prune_retired_locked()

    def report_failure(self, worker, reason=''):
        if worker is None:
            return BLAME_IGNORED
        with self._lock:
            if worker not in self._workers:
                return BLAME_IGNORED
            outcome = self._blame_locked(worker, reason)
            self._wakeup.set()
            return outcome

    def note_success(self, worker):
        if worker is None:
            return
        with self._lock:
            worker.failures = 0
            worker.outcomes.append(True)

    @property
    def revision(self):
        return self._revision


__all__ = [
    'ProxyWorker', 'WorkerLease', 'ProxyWorkerPool', 'StandbyQueue',
    'DEFAULT_CAPACITY', 'RETIRED_MEMORY_SECONDS', 'ACTIVITY_WINDOW_SECONDS',
    'STANDBY_TTL_SECONDS', 'STANDBY_LIMIT',
    'BLAME_IGNORED', 'BLAME_COUNTED', 'BLAME_RETIRED',
]
