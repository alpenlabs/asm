import flexitest

from utils.logging import setup_test_logger


class StrataTestBase(flexitest.Test):
    """Base test class that injects per-test logging."""

    def premain(self, ctx: flexitest.RunContext):
        self.logger = setup_test_logger(ctx.datadir_root, ctx.name)
