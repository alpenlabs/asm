import flexitest


class AsmTestRuntime(flexitest.TestRuntime):
    """Runtime wrapper that injects custom run context fields."""

    def create_run_context(self, name: str, env: flexitest.LiveEnv) -> flexitest.RunContext:
        return AsmRunContext(self.datadir_root, name, env)


class AsmRunContext(flexitest.RunContext):
    """RunContext carrying run name and datadir path."""

    def __init__(self, datadir_root: str, name: str, env: flexitest.LiveEnv):
        super().__init__(env)
        self.name = name
        self.datadir_root = datadir_root
