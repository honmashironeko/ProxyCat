"""
模块名称：modules.proxypool.core.services.health_scorer
功能描述：把单条代理的延迟、成功率、稳定性、可用时长、匿名等级与存活时间折算为 0-100 健康分，供列表排序与自动清理的阈值判定使用；并提供延迟均值、方差与累计有效时长的增量更新。
职责边界：负责：单条代理健康分计算与评分统计量的增量更新；不负责：读写代理记录、按分数做排序或删除决策、补测缺失数据。
关键依赖：core.domain.models.Proxy（评分输入字段来源）。
已知限制：
1. 权重之和未校验，和不为 1.0 时原始分仍会被裁剪到 0-100，各维度实际占比随之偏移。
2. 成功率取 Wilson 置信下界（z=1.96）乘 100，小样本向低收缩，个位数样本全成功也非满分。
3. 成功率样本先取请求级 probe_success_count / probe_total_count，其 total 为 0 时回退 success_count / total_checks。
4. 均值与方差不加锁：同一代理的增量更新须由调用方串行执行；方差须先于均值更新并传入不含本次新值的旧均值，否则偏差被压小、方差被低估、稳定性分偏高；离群样本触及钳位时方差可能反向高估。
5. 缺数据默认分：延迟缺失或非正、样本为 0 得 0；方差缺失得 50；uptime_ratio ≤ 0 与 age_hours ≤ 0 得 10；匿名等级不在表内（含 None）得 10。
6. 累计有效时长按两次有效验证之间持续可用近似，时差非正（时钟回拨）或超过 30 天不计入；存活时间维度在 72 小时封顶。
"""

import logging
import math
from core.domain.models import Proxy

logger = logging.getLogger(__name__)


class HealthScorer:

    DEFAULT_WEIGHT_DELAY = 0.25
    DEFAULT_WEIGHT_SUCCESS_RATE = 0.25
    DEFAULT_WEIGHT_STABILITY = 0.15
    DEFAULT_WEIGHT_UPTIME = 0.15
    DEFAULT_WEIGHT_ANONYMITY = 0.10
    DEFAULT_WEIGHT_AGE = 0.10

    ANONYMITY_SCORES = {
        'elite': 100.0,
        'anonymous': 70.0,
        'transparent': 30.0,
        'unverified': 10.0,
    }

    DELAY_EXCELLENT_THRESHOLD = 500.0
    DELAY_CUTOFF_THRESHOLD = 5000.0

    AGE_MAX_HOURS = 72.0

    VARIANCE_EXCELLENT_THRESHOLD = 100.0
    VARIANCE_CUTOFF_THRESHOLD = 10000.0

    DELAY_OUTLIER_RATIO = 3.0
    DELAY_EMA_MIN_ALPHA = 0.2

    def __init__(
        self,
        weight_delay: float | None = None,
        weight_success_rate: float | None = None,
        weight_age: float | None = None,
        weight_anonymity: float | None = None,
        weight_stability: float | None = None,
        weight_uptime: float | None = None,
    ):
        self._w_delay = weight_delay if weight_delay is not None else self.DEFAULT_WEIGHT_DELAY
        self._w_success = weight_success_rate if weight_success_rate is not None else self.DEFAULT_WEIGHT_SUCCESS_RATE
        self._w_stability = weight_stability if weight_stability is not None else self.DEFAULT_WEIGHT_STABILITY
        self._w_uptime = weight_uptime if weight_uptime is not None else self.DEFAULT_WEIGHT_UPTIME
        self._w_age = weight_age if weight_age is not None else self.DEFAULT_WEIGHT_AGE
        self._w_anonymity = weight_anonymity if weight_anonymity is not None else self.DEFAULT_WEIGHT_ANONYMITY

    def calculate(self, proxy: Proxy) -> float:
        delay_score = self._score_delay(proxy.delay_ms)
        success_score = self._score_success_rate(*self._success_samples(proxy))
        stability_score = self._score_stability(proxy.delay_variance)
        uptime_score = self._score_uptime(proxy.uptime_ratio)
        age_score = self._score_age(proxy.age_hours)
        anonymity_score = self._score_anonymity(proxy.anonymity_level)

        raw_score = (
            self._w_delay * delay_score
            + self._w_success * success_score
            + self._w_stability * stability_score
            + self._w_uptime * uptime_score
            + self._w_age * age_score
            + self._w_anonymity * anonymity_score
        )

        return round(min(100.0, max(0.0, raw_score)), 1)


    def _score_delay(self, delay_ms: float | None) -> float:
        if delay_ms is None or delay_ms <= 0:
            return 0.0
        if delay_ms <= self.DELAY_EXCELLENT_THRESHOLD:
            return 100.0
        if delay_ms >= self.DELAY_CUTOFF_THRESHOLD:
            return 0.0
        range_width = self.DELAY_CUTOFF_THRESHOLD - self.DELAY_EXCELLENT_THRESHOLD
        return 100.0 * (1.0 - (delay_ms - self.DELAY_EXCELLENT_THRESHOLD) / range_width)

    @staticmethod
    def _success_samples(proxy: Proxy) -> tuple[int, int]:
        if proxy.probe_total_count > 0:
            return proxy.probe_success_count, proxy.probe_total_count
        return proxy.success_count or 0, proxy.total_checks or 0

    def _score_success_rate(self, success_count: int, total_checks: int) -> float:
        return HealthScorer.wilson_lower_bound(success_count, total_checks) * 100.0

    @staticmethod
    def wilson_lower_bound(
        success_count: int, total_checks: int, z: float = 1.96
    ) -> float:
        if total_checks <= 0:
            return 0.0

        success_count = max(0, min(success_count, total_checks))
        n = float(total_checks)
        p = success_count / n
        z2 = z * z
        denominator = 1.0 + z2 / n
        centre = p + z2 / (2.0 * n)
        margin = z * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))

        return max(0.0, min(1.0, (centre - margin) / denominator))

    def _score_stability(self, delay_variance: float | None) -> float:
        if delay_variance is None:
            return 50.0
        if delay_variance <= self.VARIANCE_EXCELLENT_THRESHOLD:
            return 100.0
        if delay_variance >= self.VARIANCE_CUTOFF_THRESHOLD:
            return 0.0
        range_width = self.VARIANCE_CUTOFF_THRESHOLD - self.VARIANCE_EXCELLENT_THRESHOLD
        return 100.0 * (1.0 - (delay_variance - self.VARIANCE_EXCELLENT_THRESHOLD) / range_width)

    def _score_uptime(self, uptime_ratio: float) -> float:
        if uptime_ratio <= 0:
            return 10.0
        return max(0.0, min(100.0, uptime_ratio * 100.0))

    def _score_age(self, age_hours: float) -> float:
        if age_hours <= 0:
            return 10.0
        if age_hours >= self.AGE_MAX_HOURS:
            return 100.0
        return 10.0 + 90.0 * (age_hours / self.AGE_MAX_HOURS)

    def _score_anonymity(self, anonymity_level: str) -> float:
        return self.ANONYMITY_SCORES.get(anonymity_level, 10.0)


    @staticmethod
    def clamp_delay_sample(current_avg: float | None, new_delay: float) -> float:
        if current_avg is None or current_avg <= 0:
            return new_delay
        return min(new_delay, current_avg * HealthScorer.DELAY_OUTLIER_RATIO)

    @staticmethod
    def calculate_avg_delay(
        current_avg: float | None,
        new_delay: float,
        total_checks: int,
    ) -> float:
        if current_avg is None or current_avg <= 0 or total_checks <= 1:
            return new_delay

        sample = HealthScorer.clamp_delay_sample(current_avg, new_delay)
        alpha = max(
            HealthScorer.DELAY_EMA_MIN_ALPHA, 1.0 / max(1, total_checks)
        )
        return alpha * sample + (1.0 - alpha) * current_avg

    @staticmethod
    def calculate_delay_variance(
        current_variance: float | None,
        current_avg: float | None,
        new_delay: float,
        total_checks: int,
    ) -> float:
        if total_checks <= 1 or current_avg is None or current_avg <= 0:
            return 0.0

        sample = HealthScorer.clamp_delay_sample(current_avg, new_delay)
        alpha = max(
            HealthScorer.DELAY_EMA_MIN_ALPHA, 1.0 / max(1, total_checks)
        )
        delta = sample - current_avg
        previous = current_variance or 0.0

        return max(0.0, (1.0 - alpha) * (previous + alpha * delta * delta))

    @staticmethod
    def calculate_total_valid_seconds(
        current_total: float,
        last_valid_at: 'datetime | None',
        is_valid: bool,
        now: 'datetime | None' = None,
    ) -> float:
        if not is_valid or last_valid_at is None:
            return current_total

        from datetime import datetime as dt
        current_time = now or dt.now()
        elapsed = (current_time - last_valid_at).total_seconds()

        if elapsed <= 0 or elapsed > 30 * 24 * 3600:
            return current_total

        return current_total + elapsed
