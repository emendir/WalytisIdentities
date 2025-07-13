"""Run all test in all variations."""
import os
import sys

from emtest import run_pytest, set_env_var

WORKDIR = os.path.dirname(__file__)
test_files = [sub_path for sub_path in os.listdir(
    WORKDIR) if sub_path.startswith("test_")]


pytest_args = sys.argv[1:]

test_files.sort()



def run_tests() -> None:
    """Run each test file with pytest."""
    # for test_file in test_files:
    #     # Use emtest's custom test runner with specific settings:
    #     run_pytest(
    #         test_path=test_file,              # Run tests in this file
    #         pytest_args=pytest_args
    #     )
    pytest_args=sys.argv[1:]
    os.system(f"pytest {WORKDIR} {" ".join(pytest_args)}")


if True:
    import conftest #noqa
    from build_docker import build_docker_image
build_docker_image(verbose=False)

set_env_var("REBUILD_DOCKER", True)

set_env_var("WALYTIS_BETA_API_TYPE", "WALYTIS_BETA_BRENTHY_API")
print("Running tests with Brenthy...")
run_tests()

set_env_var("WALYTIS_BETA_API_TYPE", "WALYTIS_BETA_DIRECT_API")
print("Running tests with Walytis Embedded...")
run_tests()
