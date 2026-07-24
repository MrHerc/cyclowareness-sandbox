"""Detonation engines for the Cyclowareness Sandbox worker.

Each module here exposes an :class:`~worker.engines.base.Engine` subclass. The
agent builds the priority list in :mod:`worker.agent`; nothing here decides
policy, it only makes the engines importable without pulling in optional
dependencies (Qiling, requests) at package-import time.
"""
