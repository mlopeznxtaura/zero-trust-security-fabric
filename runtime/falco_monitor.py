"""
Falco runtime security monitor.
Consume Falco alerts via gRPC/webhook and trigger automated responses.
SDKs: Falco (via gRPC/HTTP), Docker SDK, Prometheus Client
"""
import os
import json
import time
import threading
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from prometheus_client import Counter, Gauge, Histogram

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

# Prometheus metrics
FALCO_ALERTS = Counter("falco_alerts_total", "Total Falco alerts", ["rule", "priority"])
FALCO_CRITICAL = Counter("falco_critical_alerts_total", "Critical Falco alerts")
CONTAINER_KILLS = Counter("container_kills_total", "Containers killed by security policy")
ALERT_LATENCY = Histogram("falco_alert_processing_ms", "Alert processing latency")


@dataclass
class FalcoAlert:
    rule: str
    priority: str         # DEBUG, INFORMATIONAL, NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY
    output: str
    output_fields: Dict[str, Any]
    timestamp: float
    hostname: str
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    proc_name: Optional[str] = None
    user_name: Optional[str] = None

    @classmethod
    def from_json(cls, data: dict) -> "FalcoAlert":
        fields = data.get("output_fields", {})
        return cls(
            rule=data.get("rule", ""),
            priority=data.get("priority", ""),
            output=data.get("output", ""),
            output_fields=fields,
            timestamp=data.get("time", time.time()),
            hostname=data.get("hostname", ""),
            container_id=fields.get("container.id"),
            container_name=fields.get("container.name"),
            proc_name=fields.get("proc.name"),
            user_name=fields.get("user.name"),
        )

    def is_critical(self) -> bool:
        return self.priority in ("CRITICAL", "ALERT", "EMERGENCY")

    def to_dict(self) -> dict:
        return {
            "rule": self.rule, "priority": self.priority,
            "output": self.output, "timestamp": self.timestamp,
            "container": self.container_name, "proc": self.proc_name,
        }


PRIORITY_ACTIONS = {
    "CRITICAL": "kill_container",
    "ALERT": "kill_container",
    "EMERGENCY": "kill_container",
    "ERROR": "pause_container",
    "WARNING": "log_and_alert",
    "NOTICE": "log",
    "INFORMATIONAL": "log",
    "DEBUG": "ignore",
}


class FalcoMonitor:
    """
    Consume Falco alerts via webhook and respond automatically.
    Policy: critical alerts kill the container; errors pause it; warnings log+alert.
    """

    def __init__(
        self,
        falco_webhook_port: int = 2801,
        auto_respond: bool = True,
        on_alert: Optional[Callable[[FalcoAlert], None]] = None,
        kill_on_critical: bool = True,
    ):
        self.auto_respond = auto_respond
        self.on_alert = on_alert
        self.kill_on_critical = kill_on_critical
        self.alerts: List[FalcoAlert] = []
        self._docker = docker.from_env() if DOCKER_AVAILABLE else None
        self._running = False
        print(f"[Falco] Monitor initialized | auto_respond={auto_respond}")

    def process_alert(self, alert: FalcoAlert):
        """Process a single Falco alert and take automated action."""
        t0 = time.perf_counter()

        self.alerts.append(alert)
        FALCO_ALERTS.labels(rule=alert.rule, priority=alert.priority).inc()
        if alert.is_critical():
            FALCO_CRITICAL.inc()

        print(f"[Falco] [{alert.priority}] {alert.rule}: {alert.output[:100]}")

        if self.on_alert:
            self.on_alert(alert)

        if self.auto_respond:
            action = PRIORITY_ACTIONS.get(alert.priority, "log")
            self._take_action(alert, action)

        ALERT_LATENCY.observe((time.perf_counter() - t0) * 1000)

    def _take_action(self, alert: FalcoAlert, action: str):
        if action == "ignore":
            return
        elif action == "log":
            pass  # Already logged above
        elif action == "log_and_alert":
            self._send_alert_notification(alert)
        elif action == "pause_container" and alert.container_id:
            self._pause_container(alert.container_id)
        elif action == "kill_container" and alert.container_id and self.kill_on_critical:
            self._kill_container(alert.container_id, alert.rule)

    def _pause_container(self, container_id: str):
        if not self._docker:
            print(f"[Falco] Would pause container {container_id} (Docker unavailable)")
            return
        try:
            container = self._docker.containers.get(container_id)
            container.pause()
            print(f"[Falco] PAUSED container {container_id}")
        except Exception as e:
            print(f"[Falco] Pause failed for {container_id}: {e}")

    def _kill_container(self, container_id: str, reason: str):
        if not self._docker:
            print(f"[Falco] Would kill container {container_id} (Docker unavailable)")
            return
        try:
            container = self._docker.containers.get(container_id)
            container.kill(signal="SIGKILL")
            CONTAINER_KILLS.inc()
            print(f"[Falco] KILLED container {container_id} | reason: {reason}")
        except Exception as e:
            print(f"[Falco] Kill failed for {container_id}: {e}")

    def _send_alert_notification(self, alert: FalcoAlert):
        """Send alert to webhook / Slack / PagerDuty."""
        webhook_url = os.environ.get("ALERT_WEBHOOK_URL")
        if webhook_url:
            try:
                httpx.post(webhook_url, json=alert.to_dict(), timeout=5.0)
            except Exception:
                pass

    def get_alert_summary(self, last_n: int = 100) -> Dict[str, Any]:
        recent = self.alerts[-last_n:]
        by_priority = {}
        for a in recent:
            by_priority[a.priority] = by_priority.get(a.priority, 0) + 1
        by_rule = {}
        for a in recent:
            by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
        return {
            "total_alerts": len(self.alerts),
            "recent": len(recent),
            "by_priority": by_priority,
            "top_rules": sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    def simulate_alert(self, rule: str = "Terminal shell in container", priority: str = "WARNING"):
        """Inject a simulated alert for testing."""
        alert = FalcoAlert(
            rule=rule, priority=priority,
            output=f"A shell was spawned in a container running as root (container=test_container)",
            output_fields={"container.name": "test_container", "container.id": "abc123",
                           "proc.name": "bash", "user.name": "root"},
            timestamp=time.time(),
            hostname="node-01",
            container_id="abc123",
            container_name="test_container",
        )
        self.process_alert(alert)
        return alert
