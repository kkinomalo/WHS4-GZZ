import unittest

from run import run_headless


class FatalController:
    def __init__(self):
        self.fatal_error = None
        self.stopped = False

    def start(self):
        self.fatal_error = "database is full"

    def snapshot(self):
        raise AssertionError("a failed collector must not report a healthy snapshot")

    def stop(self):
        self.stopped = True


class HeadlessRunnerTests(unittest.TestCase):
    def test_fatal_collector_error_propagates_for_nonzero_process_exit(self):
        controller = FatalController()

        with self.assertRaisesRegex(RuntimeError, "database is full"):
            run_headless(controller, duration=1.0)

        self.assertTrue(controller.stopped)


if __name__ == "__main__":
    unittest.main()
