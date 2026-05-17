"""
FORGE pipeline abstractions — Plan / Task DAG inspired by xAI grox.

Use these to compose new FORGE workflows declaratively:

    class PlanForgeScan(Plan):
        REQUIRED_ELIGIBILITY = TaskEligibility.FORGE_SCAN
        TASKS = {
            "task_repo_filter": TaskRepoFilter,
            "task_rate_limit": TaskRateLimit,
            "task_file_hydration": TaskFileHydration,
            "task_owasp_category_detection": TaskOwaspCategoryDetection,
            "task_policy_generation": TaskPolicyGeneration,
            "task_write_bobshell_sink": TaskWriteBobshellSink,
        }
        TASK_DEPENDENCIES = {
            "task_repo_filter": set(),
            "task_rate_limit": {"task_repo_filter"},
            "task_file_hydration": {"task_rate_limit"},
            "task_owasp_category_detection": {"task_file_hydration"},
            "task_policy_generation": {"task_owasp_category_detection"},
            "task_write_bobshell_sink": {"task_policy_generation"},
        }

This module does NOT replace the existing forge.py orchestrator. It is an
opt-in abstraction for future v2 work. Existing 95/95 tests are unaffected.
"""

from .plan import Plan, TaskEligibility, PlanResult
from .task import Task, TaskContext, TaskResultCategory, TaskStopExecution
from .pipeline import Pipeline, Source, Hydrator, Filter, Scorer, Selector, SideEffect
from .pipeline import FilterResult, SelectResult

__all__ = [
    "Plan",
    "PlanResult",
    "Task",
    "TaskContext",
    "TaskEligibility",
    "TaskResultCategory",
    "TaskStopExecution",
    "Pipeline",
    "Source",
    "Hydrator",
    "Filter",
    "Scorer",
    "Selector",
    "SideEffect",
    "FilterResult",
    "SelectResult",
]
