"""Shared builders for the tests."""
from datetime import datetime

from data.infrastructure import build_infrastructure, get_component

NOW = datetime(2026, 1, 1, 12, 0, 0)


def environment():
    return build_infrastructure()


def comp(components, name):
    return get_component(components, name)
