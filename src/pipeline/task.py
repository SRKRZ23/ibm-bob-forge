"""
Task — atomic unit of work in a FORGE Plan DAG.

Each Task subclass is an async, retriable, skippable unit. The base class
handles metrics, retries, and skip-rule dispatch so subclasses only
implement domain logic in `_exec()`.

Inspired by xAI grox.tasks.task.Task (Apache 2.0). Re-implemented for
FORGE without the production-specific Metrics / Logging dependencies —
swap stdlib `logging` for OpenTelemetry when promoting to a service.
"""
from __future__ import annotations

import logging
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TaskResultCategory(str, Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


class TaskStopExecution(Exception):
    """Raise from inside a Task's _exec to stop without failing the plan."""


@dataclass
class TaskContext:
    """
    Carries shared state across tasks in a single plan execution.

    Tasks append findings, intermediate artifacts, and errors here.
    The orchestrator (Plan) provides a fresh TaskContext per execute() call.
    """
    payload: Any = None
    findings: list = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    errors: list[Exception] = field(default_factory=list)
    start_time: float = field(default_factory=time.perf_counter)


class Task(ABC):
    """
    Abstract Task. Subclasses implement `_exec` (and optionally `_should_skip`).

    Built-in behavior:
    - 2-attempt retry on transient failure (override `max_retries` to change)
    - skip routing via `should_skip` (returns True to skip)
    - timing + log statements wrapped around _exec
    """

    max_retries: int = 2

    @classmethod
    async def exec(cls, ctx: TaskContext) -> TaskResultCategory:
        name = cls.get_name()
        start = time.perf_counter()
        if cls.should_skip(ctx):
            logger.info(f"[{name}] skipped")
            return TaskResultCategory.SKIPPED

        last_exc: Exception | None = None
        for attempt in range(1, cls.max_retries + 1):
            try:
                await cls._exec(ctx)
                duration = time.perf_counter() - start
                logger.info(f"[{name}] succeeded in {duration:.3f}s (attempt {attempt})")
                return TaskResultCategory.SUCCESS
            except TaskStopExecution as e:
                logger.info(f"[{name}] stopped early: {e}")
                return TaskResultCategory.SKIPPED
            except Exception as e:
                last_exc = e
                logger.warning(
                    f"[{name}] attempt {attempt}/{cls.max_retries} failed: {e}"
                )
                if attempt == cls.max_retries:
                    logger.error(
                        f"[{name}] all attempts failed:\n{traceback.format_exc()}"
                    )
                    ctx.errors.append(e)
                    return TaskResultCategory.FAILED

        if last_exc is not None:
            raise last_exc
        return TaskResultCategory.FAILED

    @classmethod
    @abstractmethod
    async def _exec(cls, ctx: TaskContext) -> None:
        """Domain logic. Mutate ctx.findings / ctx.artifacts. Don't catch
        exceptions you don't understand — let the orchestrator handle retries."""

    @classmethod
    def should_skip(cls, ctx: TaskContext) -> bool:
        """Override to skip based on context (e.g. feature flag off, missing prerequisite)."""
        return False

    @classmethod
    def get_name(cls) -> str:
        # Convert CamelCase to snake_case for log readability.
        out = []
        for i, c in enumerate(cls.__name__):
            if i and c.isupper():
                out.append("_")
            out.append(c.lower())
        return "".join(out)
