"""
Recsys-style Pipeline traits — Python imitation of xAI's Rust
candidate-pipeline crate (Apache 2.0).

Use this when FORGE-style scanning is reframed as a "candidate ranking"
problem (e.g. confidence-scored findings, ranked refactor suggestions,
or alternative recommendation systems).

This module is opt-in and orthogonal to Plan/Task DAG. Pick whichever
fits the workflow:

- Plan/Task DAG   -> sequential workflow with dependencies + retries
- Pipeline traits -> many-stage transformation over a list of candidates
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import wraps
from typing import Generic, TypeVar

logger = logging.getLogger(__name__)

Q = TypeVar("Q")
C = TypeVar("C")


def _stage_log(stage: str):
    """Decorator that wraps an async stage method with timing logs."""

    def deco(fn):
        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            start = time.perf_counter()
            try:
                result = await fn(self, *args, **kwargs)
                duration = time.perf_counter() - start
                logger.info(
                    f"[{stage}.{self.__class__.__name__}] ok in {duration:.4f}s"
                )
                return result
            except Exception as e:
                duration = time.perf_counter() - start
                logger.error(
                    f"[{stage}.{self.__class__.__name__}] failed after {duration:.4f}s: {e}"
                )
                raise

        return wrapper

    return deco


class Source(ABC, Generic[Q, C]):
    """1 -> many: fetch candidates from a backend."""

    def enable(self, query: Q) -> bool:
        return True

    @abstractmethod
    async def source(self, query: Q) -> list[C]:
        ...


class Hydrator(ABC, Generic[Q, C]):
    """many -> many: enrich candidates. MUST preserve length and order."""

    def enable(self, query: Q) -> bool:
        return True

    @abstractmethod
    async def hydrate(self, query: Q, candidates: list[C]) -> list[C]:
        ...


@dataclass
class FilterResult(Generic[C]):
    kept: list[C]
    removed: list[C]


class Filter(ABC, Generic[Q, C]):
    """many -> fewer: partition into kept and removed."""

    def enable(self, query: Q) -> bool:
        return True

    @abstractmethod
    def filter(self, query: Q, candidates: list[C]) -> FilterResult[C]:
        ...


class Scorer(ABC, Generic[Q, C]):
    """many -> many: assign scores. MUST preserve order."""

    def enable(self, query: Q) -> bool:
        return True

    @abstractmethod
    async def score(self, query: Q, candidates: list[C]) -> list[C]:
        ...


@dataclass
class SelectResult(Generic[C]):
    selected: list[C]
    non_selected: list[C]


class Selector(ABC, Generic[Q, C]):
    """many -> K: sort and truncate."""

    def enable(self, query: Q) -> bool:
        return True

    @abstractmethod
    def score(self, candidate: C) -> float:
        ...

    def size(self) -> int | None:
        return None

    def select(self, query: Q, candidates: list[C]) -> SelectResult[C]:
        ordered = sorted(candidates, key=self.score, reverse=True)
        k = self.size()
        if k is None:
            return SelectResult(selected=ordered, non_selected=[])
        return SelectResult(selected=ordered[:k], non_selected=ordered[k:])


class SideEffect(ABC, Generic[Q, C]):
    """Fire-and-forget action that does not affect the returned result.

    Exceptions are caught and logged, never re-raised, so a failing audit
    write doesn't fail the user-facing scan.
    """

    def enable(self, query: Q) -> bool:
        return True

    @abstractmethod
    async def run(
        self, query: Q, selected: list[C], non_selected: list[C]
    ) -> None:
        ...


@dataclass
class Pipeline(Generic[Q, C]):
    sources: list[Source[Q, C]]
    hydrators: list[Hydrator[Q, C]]
    filters: list[Filter[Q, C]]
    scorers: list[Scorer[Q, C]]
    selector: Selector[Q, C]
    side_effects: list[SideEffect[Q, C]]

    async def execute(self, query: Q) -> SelectResult[C]:
        # Sources run in parallel.
        sourced = await asyncio.gather(
            *[s.source(query) for s in self.sources if s.enable(query)]
        )
        candidates: list[C] = [c for batch in sourced for c in batch]
        logger.info(f"[pipeline] sourced {len(candidates)} candidates")

        # Hydrators run sequentially (each one may depend on previous's output).
        for h in self.hydrators:
            if not h.enable(query):
                continue
            hydrated = await h.hydrate(query, candidates)
            if len(hydrated) != len(candidates):
                logger.warning(
                    f"[{h.__class__.__name__}] length mismatch "
                    f"{len(hydrated)} != {len(candidates)} — dropping batch"
                )
                continue
            candidates = hydrated

        # Filters run sequentially.
        for f in self.filters:
            if not f.enable(query):
                continue
            result = f.filter(query, candidates)
            logger.info(
                f"[{f.__class__.__name__}] kept={len(result.kept)} removed={len(result.removed)}"
            )
            candidates = result.kept

        # Scorers run sequentially.
        for sc in self.scorers:
            if not sc.enable(query):
                continue
            scored = await sc.score(query, candidates)
            if len(scored) != len(candidates):
                logger.warning(
                    f"[{sc.__class__.__name__}] length mismatch "
                    f"{len(scored)} != {len(candidates)} — keeping pre-score"
                )
                continue
            candidates = scored

        # Select top-K.
        result = self.selector.select(query, candidates)
        logger.info(
            f"[pipeline] selected={len(result.selected)} non_selected={len(result.non_selected)}"
        )

        # SideEffects fire-and-forget.
        if self.side_effects:
            await asyncio.gather(
                *[
                    se.run(query, result.selected, result.non_selected)
                    for se in self.side_effects
                    if se.enable(query)
                ],
                return_exceptions=True,
            )

        return result
