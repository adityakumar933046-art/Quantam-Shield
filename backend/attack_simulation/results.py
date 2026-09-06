"""
Simulation Results and Defensive Performance Metrics Processor.
Aggregates historical simulation statistics, detection rates, and latency.
"""

from typing import List, Dict, Any


def calculate_simulation_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes defensive performance metrics from simulated attack executions.
    """
    total = len(results)
    if total == 0:
        return {
            "total_simulations": 0,
            "threats_correctly_detected": 0,
            "detection_rate": 0.0,
            "missed_simulations": 0,
            "average_detection_time_ms": 0.0,
            "average_risk_score": 0.0,
            "attack_type_breakdown": {},
            "disclaimer": "Defensive evaluation metrics reflect controlled test simulations and do not represent real-world production attack rates."
        }

    detected_count = sum(1 for r in results if r.get("detection_success", False))
    missed_count = total - detected_count
    detection_rate = round((detected_count / total) * 100.0, 2)

    exec_times = [r.get("execution_time_ms", 0.0) for r in results if r.get("execution_time_ms") is not None]
    avg_time = round(sum(exec_times) / len(exec_times), 2) if exec_times else 0.0

    risk_scores = [r.get("final_risk_score", 0.0) for r in results if r.get("final_risk_score") is not None]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0

    # Breakdown by attack type
    breakdown: Dict[str, Dict[str, Any]] = {}
    for r in results:
        atype = r.get("attack_type", "UNKNOWN")
        if atype not in breakdown:
            breakdown[atype] = {"total": 0, "detected": 0, "detection_rate": 0.0}
        breakdown[atype]["total"] += 1
        if r.get("detection_success", False):
            breakdown[atype]["detected"] += 1

    for atype, stats in breakdown.items():
        if stats["total"] > 0:
            stats["detection_rate"] = round((stats["detected"] / stats["total"]) * 100.0, 2)

    return {
        "total_simulations": total,
        "threats_correctly_detected": detected_count,
        "detection_rate": detection_rate,
        "missed_simulations": missed_count,
        "average_detection_time_ms": avg_time,
        "average_risk_score": avg_risk,
        "attack_type_breakdown": breakdown,
        "disclaimer": "Defensive evaluation metrics reflect controlled test simulations and do not represent real-world production attack rates."
    }


class ResultsAggregator:
    """In-memory aggregator for batch testing and simulation metric evaluation."""
    def __init__(self):
        self.results: List[Dict[str, Any]] = []

    def add_result(self, result: Any):
        if hasattr(result, "to_dict"):
            d = result.to_dict()
        elif isinstance(result, dict):
            d = result
        else:
            d = {
                "attack_type": getattr(result, "attack_type", "UNKNOWN"),
                "detection_success": getattr(result, "detection_success", True),
                "execution_time_ms": getattr(result, "execution_time_ms", 0.0),
                "final_risk_score": getattr(result, "final_risk_score", 0.0),
            }
        self.results.append(d)

    def get_summary(self) -> Dict[str, Any]:
        return calculate_simulation_metrics(self.results)

