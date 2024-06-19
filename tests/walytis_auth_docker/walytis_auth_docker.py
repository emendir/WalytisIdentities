import os
import docker
from time import sleep


class ContactsDocker:
    def __init__(self, auto_run: bool = True):
        self.image_name = "local/walytis_auth_testing"
        self._docker_client = docker.from_env()
        self.container = self._docker_client.containers.create(self.image_name, privileged=True)
        if auto_run:
            self.start()

    def start(self) -> None:
        """Start this container."""
        self.container.start()

        # wait till docker container's Brenthy has renamed its update blockhain
        # and restarted
        while not self.run_python_command(
            "import os;"
            "print(os.path.exists('/opt/Brenthy/BlockchainData/Walytis_Beta/BrenthyUpdatesTEST'))"
        ) == "True":
            sleep(0.2)
        sleep(0.2)

    def stop(self) -> None:
        """Stop this container."""
        self.container.stop()

    def restart(self) -> None:
        """Restart this container."""
        self.container.restart()

    def delete(self) -> None:
        self.container.stop()
        self.container.remove()

    def run_shell_command(self, command: str) -> str:
        """Run a shell command, returning its output."""
        if not self.is_running():
            raise ContainerNotRunningError()
        exec_command = ["sh", "-c", command]
        exec_result = self.container.exec_run(exec_command)
        return exec_result.output.decode('utf-8').strip()

    def is_running(self) -> bool:
        """Check if this docker container is running or not."""
        return self._docker_client.containers.get(self.container.id).attrs["State"]["Running"]

    def run_python_command(self, command: str) -> str:
        """Run a python command, returning its output."""
        python_command = "python -c \"" + command + "\""
        return self.run_shell_command(python_command)


def delete_containers() -> None:
    """Delete all Brenthy docker containers."""
    os.system(
        "docker stop "
        "$(docker ps --filter 'ancestor=local/walytis_auth_testing' -aq) "
        ">/dev/null 2>&1; "
        "docker rm $(docker ps --filter 'ancestor=local/walytis_auth_testing' -aq) "
        ">/dev/null 2>&1"
    )
    os.system(
        "docker stop $(docker ps  --filter 'name=*brenthy*' "
        "--filter 'name= ^ brenthy' --filter 'name=brenthy$' -aq) "
        ">/dev/null 2>&1; "
        "docker rm $(docker ps --filter 'name=*brenthy*' "
        "--filter 'name= ^ brenthy' --filter 'name=brenthy$' -aq) "
        ">/dev/null 2>&1"
    )


class ContainerNotRunningError(Exception):
    """When the container isn't running."""


# Example usage:
if __name__ == "__main__":
    # Create an instance of DockerContainer with the desired image
    docker_container = ContactsDocker(auto_run=False)

    # Start the container
    docker_container.start()

    # Execute shell command on the container
    shell_output = docker_container.run_shell_command("systemctl status brenthy")
    print("Output of Shell command:", shell_output)

    # Execute Python command on the container
    python_output = docker_container.run_python_command(
        "import walytis_beta_api;print(walytis_beta_api.get_walytis_beta_version())")
    print("Output of Python command:", python_output)

    # Stop the container
    docker_container.stop()
