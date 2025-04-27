import tarfile
import io
import tempfile
import shutil
import os
import docker
from time import sleep
from loguru import logger
from walytis_beta_embedded import ipfs
from termcolor import colored as coloured
import pyperclip
from brenthy_docker import BrenthyDocker, delete_containers


class WalIdentityDocker(BrenthyDocker):
    def __init__(
        self,
        image: str = "local/walytis_auth_testing",
        **kwargs
    ):
        BrenthyDocker.__init__(self, image=image, **kwargs)


class ContainerNotRunningError(Exception):
    """When the container isn't running."""


# Example usage:
if __name__ == "__main__":
    # Create an instance of DockerContainer with the desired image
    delete_containers(container_name_substr="DemoWalidentity")
    docker_container = WalIdentityDocker(
        container_name="DemoWalidentity",
        auto_run=False
    )

    container_id = docker_container.container.id
    # Start the container
    docker_container.start(await_brenthy=True, await_ipfs=True)

    print("Container's IPFS ID: ", docker_container.ipfs_id)

    # Execute shell command on the container
    shell_output = docker_container.run_shell_command(
        "ls")
    print("Output of Shell command:", shell_output)

    # Execute Python command on the container
    python_output = docker_container.run_python_command(
        "import walytis_beta_embedded._walytis_beta.walytis_beta_api;"
        "print(walytis_beta_embedded._walytis_beta.walytis_beta_api.get_walytis_beta_version())"
    )
    print("Output of Python command:", python_output)

    docker_container.transfer_file(
        "build_docker.py", "/tmp/test/wad.py")
    docker_container.run_shell_command("ls /tmp/test/")

    remote_tempfile = docker_container.write_to_tempfile("Hello there!")
    docker_container.run_shell_command(f"cat {remote_tempfile}")
    # Stop the container
    docker_container.stop()

    docker_container = BrenthyDocker(container_id=container_id)
    docker_container.start()
    shell_output = docker_container.run_shell_command(
        "systemctl status brenthy")
    print("Output of Shell command:", shell_output)
    docker_container.stop()
