import os
import sys

import flexitest

from constants import TEST_DIR
from envs import BasicEnv
from envs.testenv import AsmTestRuntime
from factory.asm_rpc import AsmRpcFactory
from factory.bitcoin import BitcoinFactory
from utils.logging import setup_root_logger


def main(argv: list[str]) -> int:
    setup_root_logger()
    root_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(root_dir, TEST_DIR)

    datadir_root = flexitest.create_datadir_in_workspace(os.path.join(root_dir, "_dd"))

    modules = flexitest.runtime.scan_dir_for_modules(test_dir)
    tests = flexitest.runtime.load_candidate_modules(modules)

    bfac = BitcoinFactory([12300 + i for i in range(100)])
    asmfac = AsmRpcFactory([12400 + i for i in range(100)])
    factories = {"bitcoin": bfac, "asm_rpc": asmfac}

    env_configs: dict[str, flexitest.EnvConfig] = {"basic": BasicEnv()}

    rt = AsmTestRuntime(env_configs, datadir_root, factories)
    rt.prepare_registered_tests()

    arg_test_names = argv[1:]
    if arg_test_names:
        tests = [extract_test_name(arg) for arg in arg_test_names]

    results = rt.run_tests(tests)
    rt.save_json_file("results.json", results)
    flexitest.dump_results(results)
    flexitest.fail_on_error(results)
    return 0


def extract_test_name(test_path: str) -> str:
    return os.path.splitext(os.path.basename(test_path))[0]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
