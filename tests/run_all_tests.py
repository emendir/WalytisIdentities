"""Run all tests in all variations."""

import os
import sys

from emtest import set_env_var

WORKDIR = os.path.dirname(__file__)

pytest_args = sys.argv[1:]


def run_tests() -> None:
    """Run each test file with pytest."""
    pytest_args = sys.argv[1:]
    os.system(f"pytest {WORKDIR} {' '.join(pytest_args)}")


os.system("sudo systemctl restart ipfs brenthy")
if True:
    os.chdir(WORKDIR)
    import conftest  # noqa
    from prebuilt_group_did_managers import create_did_managers
    from walid_docker.build_docker import build_docker_image

create_did_managers()
build_docker_image(verbose=False)

set_env_var("TESTS_REBUILD_DOCKER", False)

set_env_var("WALYTIS_TEST_MODE", "RUN_BRENTHY")
print("Running tests with Brenthy...")
os.system("sudo systemctl restart ipfs brenthy")
run_tests()

# set_env_var("WALYTIS_TEST_MODE", "EMBEDDED")
# print("Running tests with Walytis Embedded...")
# os.system("sudo systemctl stop ipfs brenthy")
# run_tests()
