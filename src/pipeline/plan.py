"""
Plan — a declarative DAG of Tasks.

Subclass Plan and declare:
- TASKS:              dict[str, type[Task]]      task name -> Task class
- TASK_DEPENDENCIES:  dict[str, set[str]]        task name -> set of dep names
- REQUIRED_ELIGIBILITY: TaskEligibility          which payloads this plan handles

Then call `await PlanInstance().execute(payload)`. Tasks with no remaining
dependencies run in parallel via `asyncio.gather`.

Inspired by xAI grox.plans.plan.Plan (Apache 2.0).
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .task import Task, TaskContext, TaskResultCategory

logger = logging.getLogger(__name__)


class TaskEligibility(str, Enum):
    """
    Coarse-grained label that lets a master plan dispatch a payload
    to the right sub-plan. Extend as FORGE grows.
    """
    FORGE_SCAN = "forge_scan"
    FORGE_VERIFY = "forge_verify"
    FORGE_DEMO = "forge_demo"


@dataclass
class PlanResult:
    plan_name: str
    success: bool
    duration_seconds: float
    task_results: dict[str, TaskResultCategory] = field(default_factory=dict)
    errors: list[Exception] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    findings: list = field(default_factory=list)


class Plan(ABC):
    TASKS: dict[str, type[Task]] = {}
    TASK_DEPENDENCIES: dict[str, set[str]] = {}
    REQUIRED_ELIGIBILITY: TaskEligibility | None = None

    def __init__(self) -> None:
        if not self.TASKS:
            raise ValueError(f"{self.__class__.__name__} has empty TASKS dict")
        all_dep_names = {d for deps in self.TASK_DEPENDENCIES.values() for d in deps}
        unknown_deps = all_dep_names - set(self.TASKS.keys())
        if unknown_deps:
            raise ValueError(
                f"TASK_DEPENDENCIES references unknown tasks: {unknown_deps}"
            )
        for task_name in self.TASK_DEPENDENCIES:
            if task_name not in self.TASKS:
                raise ValueError(
                    f"TASK_DEPENDENCIES has key {task_name!r} not in TASKS"
                )
        self._cycle_check()

    def _cycle_check(self) -> None:
        """Topological sort sanity check — raise ValueError on cycle."""
        in_degree = {name: 0 for name in self.TASKS}
        for name in self.TASKS:
            for dep in self.TASK_DEPENDENCIES.get(name, set()):
                in_degree[name] += 1
        queue = [n for n, d in in_degree.items() if d == 0]
        visited = 0
        while queue:
            cur = queue.pop(0)
            visited += 1
            for name in self.TASKS:
                if cur in self.TASK_DEPENDENCIES.get(name, set()):
                    in_degree[name] -= 1
                    if in_degree[name] == 0:
                        queue.append(name)
        if visited != len(self.TASKS):
            raise ValueError(
                f"{self.__class__.__name__} has a dependency cycle"
            )

    def is_eligible(self, eligibility: TaskEligibility | None) -> bool:
        if self.REQUIRED_ELIGIBILITY is None:
            return True
        return eligibility == self.REQUIRED_ELIGIBILITY

    async def execute(self, payload: Any) -> PlanResult:
        plan_name = self.__class__.__name__
        start = time.perf_counter()
        logger.info(f"[{plan_name}] executing DAG with {len(self.TASKS)} tasks")

        ctx = TaskContext(payload=payload)
        loop = asyncio.get_running_loop()
        # One future per task — completes when the task finishes (success or not).
        futures: dict[str, asyncio.Future[TaskResultCategory]] = {
            name: loop.create_future() for name in self.TASKS
        }
        task_results: dict[str, TaskResultCategory] = {}

        async def run_one(name: str) -> None:
            deps = self.TASK_DEPENDENCIES.get(name, set())
            if deps:
                await asyncio.gather(*[futures[d] for d in deps])
                # If any dep failed, skip this task.
                if any(
                    task_results.get(d) == TaskResultCategory.FAILED for d in deps
                ):
                    task_results[name] = TaskResultCategory.SKIPPED
                    futures[name].set_result(TaskResultCategory.SKIPPED)
                    logger.info(f"[{name}] skipped due to failed dependency")
                    return
            result = await self.TASKS[name].exec(ctx)
            task_results[name] = result
            futures[name].set_result(result)

        try:
            await asyncio.gather(*[run_one(n) for n in self.TASKS])
            success = all(r != TaskResultCategory.FAILED for r in task_results.values())
        except Exception as e:
            ctx.errors.append(e)
            success = False

        duration = time.perf_counter() - start
        logger.info(
            f"[{plan_name}] done in {duration:.3f}s — "
            f"success={success}, results={task_results}"
        )

        return PlanResult(
            plan_name=plan_name,
            success=success,
            duration_seconds=duration,
            task_results=task_results,
            errors=ctx.errors,
            artifacts=ctx.artifacts,
            findings=ctx.findings,
        )
