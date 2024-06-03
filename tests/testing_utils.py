from tqdm import tqdm, TMonitor
import threading
from termcolor import colored as coloured
import time

BREAKPOINTS = False
PYTEST = True  # whether or not this script is being run by pytest


def mark(success: bool, message: str, error: Exception | None = None) -> None:
    """Handle test results in a way compatible with and without pytest.

    Prints a check or cross and message depending on the given success.
    If pytest is running this test, an exception is thrown if success is False.

    Args:
        success: whether or not the test succeeded
        message: short description of the test to print
        error: Exception to raise/print in case of failure
    """
    if success:
        mark = coloured("✓", "green")
    else:
        mark = coloured("✗", "red")

    print(mark, message)
    if not success:
        if PYTEST:
            if error:
                raise error
            raise Exception(f'Failed at test: {message}')
        if error:
            print(str(error))
        if BREAKPOINTS:
            breakpoint()


def test_threads_cleanup() -> None:
    """Test that all threads have exited."""
    for _ in range(2):
        polite_wait(5)
        threads = [
            x for x in threading.enumerate() if not isinstance(x, TMonitor)
        ]
        success = len(threads) == 1
        if success:
            break
    mark(success, "thread cleanup")
    if not success:
        [print(x) for x in threads]


def polite_wait(n_sec: int) -> None:
    """Wait for the given duration, displaying a progress bar."""
    # print(f"{n_sec}s patience...")
    for i in tqdm(range(n_sec), leave=False):
        time.sleep(1)
