import time

import pytest
import time_machine


@pytest.fixture
def travel_to_frozen():
    """Freeze time at the instant the mock test tokens were minted."""
    with time_machine.travel(time.time(), tick=False):
        yield
