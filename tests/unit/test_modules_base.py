"""Unit tests for Layer 9 — stof.modules.base."""
import pytest

from stof.modules.base import VulnModule


def test_vulnmodule_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        VulnModule()


def test_subclass_without_run_cannot_be_instantiated():
    class Incomplete(VulnModule):
        module_id = "incomplete"
        name = "Incomplete"
        phase = 1

    with pytest.raises(TypeError):
        Incomplete()


def test_subclass_implementing_run_can_be_instantiated():
    class Complete(VulnModule):
        module_id = "complete"
        name = "Complete"
        phase = 1

        async def run(self, endpoints, session_manager, session_pool):
            return []

    instance = Complete()
    assert instance.module_id == "complete"
