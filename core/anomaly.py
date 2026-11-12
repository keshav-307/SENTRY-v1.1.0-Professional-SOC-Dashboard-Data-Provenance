import math
from collections import defaultdict
from datetime import datetime


MODEL_NAME = "sentry-statistical-baseline"
MODEL_VERSION = "1.0"

FEATURES = (
    "event_count",
    "unique_destination_ports",
    "unique_destination_ips",
    "failed_auth_count",
    "dns_query_count",
)

MIN_BASELINE_SAMPLES = 5


class AnomalyDetector:
    """
    Optional statistical anomaly layer.

    This is intentionally simple and explainable: it builds a baseline
    of per-source activity features and flags sources whose feature
    values deviate strongly from that baseline.

    It does not replace the rule engine, and an anomaly score is not a
    probability of malicious activity. It is a deviation signal that
    analysts must interpret alongside rules and context.
    """

    def __init__(self, z_threshold=4.0):
        self.z_threshold = z_threshold
        self.model_name = MODEL_NAME
        self.model_version = MODEL_VERSION

    # ---------------------------------------------------------
    # FEATURES
    # ---------------------------------------------------------

    def extract_features(self, events):
        """
        Return {source_ip: {feature: value}} for the supplied events.
        """

        grouped = defaultdict(list)

        for event in events:
            if event.source_ip:
                grouped[event.source_ip].append(event)

        features = {}

        for source_ip, source_events in grouped.items():
            features[source_ip] = {
                "event_count": len(source_events),
                "unique_destination_ports": len(
                    {
                        event.destination_port
                        for event in source_events
                        if event.destination_port is not None
                    }
                ),
                "unique_destination_ips": len(
                    {
                        event.destination_ip
                        for event in source_events
                        if event.destination_ip
                    }
                ),
                "failed_auth_count": sum(
                    1
                    for event in source_events
                    if event.event_type == "login_failure"
                ),
                "dns_query_count": sum(
                    1
                    for event in source_events
                    if event.event_type == "dns_query"
                ),
            }

        return features

    # ---------------------------------------------------------
    # BASELINE
    # ---------------------------------------------------------

    def update_baseline(self, baseline, events, max_samples=1000):
        """
        Update a stored baseline with the supplied events.

        The baseline stores running mean and standard deviation for
        each feature. Values are pooled with previous observations so
        the baseline tracks gradually changing normal activity.
        """

        features = self.extract_features(events)

        if not features:
            return baseline

        rows = list(features.values())

        count = max(1, int(baseline.get("count", 0))) if baseline else 0

        new_count = count + len(rows)

        previous_mean = (
            baseline.get("mean", {})
            if baseline
            else {}
        )

        current_mean = {}

        for feature in FEATURES:
            total = sum(row[feature] for row in rows)
            batch_mean = total / len(rows)
            previous = float(previous_mean.get(feature, 0.0))

            if count == 0:
                current_mean[feature] = batch_mean
            else:
                current_mean[feature] = (
                    previous * count + batch_mean * len(rows)
                ) / new_count

        # Second pass for pooled variance.
        std = {}

        previous_std = (
            baseline.get("std", {})
            if baseline
            else {}
        )

        for feature in FEATURES:
            prior_variance = float(previous_std.get(feature, 0.0)) ** 2
            prior_weight = count
            batch_variance = sum(
                (row[feature] - current_mean[feature]) ** 2
                for row in rows
            ) / len(rows)
            combined = (
                prior_variance * prior_weight
                + batch_variance * len(rows)
            ) / new_count
            std[feature] = math.sqrt(max(combined, 0.0))

        return {
            "count": min(new_count, max_samples),
            "mean": current_mean,
            "std": std,
            "updated_at": datetime.now().isoformat(),
        }

    # ---------------------------------------------------------
    # SCORING
    # ---------------------------------------------------------

    def score(self, features, baseline):
        """
        Score one feature row against a baseline.

        Returns (score, reasons). The score is the largest absolute
        z-score across features. A feature whose baseline variation is
        zero is only flagged when it changes from the baseline value.
        """

        if not baseline:
            return 0.0, []

        mean = baseline.get("mean", {})
        std = baseline.get("std", {})

        score = 0.0
        reasons = []

        for feature in FEATURES:
            value = float(features.get(feature, 0.0))
            expected = float(mean.get(feature, 0.0))
            deviation = float(std.get(feature, 0.0))

            if deviation <= 0.0:
                z_score = 0.0 if value == expected else float("inf")
            else:
                z_score = abs(value - expected) / deviation

            if z_score >= self.z_threshold:
                score = max(score, z_score if math.isfinite(z_score) else 99.0)
                reasons.append(
                    {
                        "feature": feature,
                        "observed": value,
                        "baseline_mean": expected,
                        "baseline_std": deviation,
                        "z_score": (
                            z_score if math.isfinite(z_score) else None
                        ),
                    }
                )

        return score, reasons

    def detect(self, events, baseline):
        """
        Return anomaly findings for events, or an empty list when no
        usable baseline exists yet.
        """

        if not baseline:
            return []

        if baseline.get("count", 0) < MIN_BASELINE_SAMPLES:
            return []

        features = self.extract_features(events)

        findings = []

        for source_ip, row in features.items():
            score, reasons = self.score(row, baseline)

            if not reasons:
                continue

            findings.append(
                {
                    "source_ip": source_ip,
                    "score": round(score, 3),
                    "threshold": self.z_threshold,
                    "features": row,
                    "baseline": {
                        "count": baseline.get("count"),
                        "mean": baseline.get("mean", {}),
                        "std": baseline.get("std", {}),
                    },
                    "reasons": reasons,
                    "model": {
                        "name": self.model_name,
                        "version": self.model_version,
                    },
                    "detected_at": datetime.now().isoformat(),
                }
            )

        findings.sort(key=lambda finding: finding["score"], reverse=True)

        return findings
