import tarfile
import io
import tempfile
import shutil
import os
import docker
from time import sleep
from loguru import logger
import ipfs_api
from termcolor import colored as coloured


class ContactsDocker:
    def __init__(self, auto_run: bool = True):
        self.image_name = "local/walytis_auth_testing"
        self._docker_client = docker.from_env()
        self.container = self._docker_client.containers.create(
            self.image_name, privileged=True)
        if auto_run:
            self.start()

    def start(self, await_brenthy=True, await_ipfs=True) -> None:
        """Start this container."""
        logger.info("Starting container...")
        self.container.start()

        if await_brenthy:
            # wait till docker container's Brenthy has renamed its update blockhain
            # and restarted
            while not self.run_python_command(
                ("import os;"
                 "print(os.path.exists('/opt/Brenthy/BlockchainData/Walytis_Beta/BrenthyUpdatesTEST'))"),
                print_output=False
            ) == "True":
                sleep(0.2)
            sleep(0.2)
        if await_ipfs:
            logger.info("Connecting to container via IPFS...")
            self._docker_swarm_connect()
        logger.info("Started container!")

    def stop(self) -> None:
        """Stop this container."""
        self.container.stop()

    def restart(self) -> None:
        """Restart this container."""
        self.container.restart()

    def delete(self) -> None:
        self.container.stop()
        self.container.remove()

    def transfer_file(self, local_filepath: str, remote_filepath: str) -> None:
        """Copy a local file into the docker container."""
        dst_dir = os.path.dirname(remote_filepath)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w|') as tar, open(local_filepath, 'rb') as f:
            info = tar.gettarinfo(fileobj=f)
            info.name = os.path.basename(remote_filepath)
            tar.addfile(info, f)
        # create remote directory if needed
        self.run_shell_command(f"mkdir -p {os.path.dirname(remote_filepath)}")
        self.container.put_archive(dst_dir, stream.getvalue())

    def write_to_tempfile(self, data: str | bytes) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        tempdir = tempfile.mkdtemp()
        local_tempfile = os.path.join(tempdir, "tempf")

        with open(local_tempfile, "wb+") as file:
            file.write(data)
        remote_tempfile = self._run_shell_command("mktemp").strip().decode()
        self.transfer_file(local_tempfile, remote_tempfile)

        shutil.rmtree(tempdir)
        return remote_tempfile

    def is_running(self) -> bool:
        """Check if this docker container is running or not."""
        return self._docker_client.containers.get(self.container.id).attrs["State"]["Running"]

    def _run_shell_command(self, command: str):
        exec_id = self._docker_client.api.exec_create(self.container.id, command)['Id']
        output = self._docker_client.api.exec_start(exec_id)
        return output

    def run_shell_command(
        self, command: str,
        user: str | None = None,
        print_output=True,
        colour="light_yellow"
    ) -> str:
        """Run shell code from within the container's operating system.

        Not suitable for code that contains double quotes.
        """
        if user:
            command = f"su {user} -c \"{command}\""
        command = f"docker exec -it {self.container.id} {command}"
        import pexpect
        child = pexpect.spawn(command, encoding='utf-8')
        result = ""
        # Capture the output line by line
        while True:
            try:
                line = child.readline()
                if not line:
                    break
                if print_output:
                    if colour:
                        print(coloured(line.strip(), colour))
                    else:
                        print(line.strip())
                result += line

            except pexpect.EOF:
                break

        # Ensure the process has finished
        child.wait()

        # result = subprocess.run(
        #     command, shell=True, capture_output=True, text=True, check=check
        # )
        return result.strip()

    def run_bash_code(
        self,
        code: str | list[str],
        print_output: bool = True,
        colour: str = "light_yellow"
    ) -> str:
        """Run any bash code in the docker container, returning its output.

        Suitable for code that contains any quotes and escape characters.
        """
        if isinstance(code, list):
            # concatenate list elements into single string
            code = "\n".join(code)
        remote_tempfile = self.write_to_tempfile(code)
        return self.run_shell_command(
            f"/bin/bash {remote_tempfile}",
            print_output=print_output, colour=colour
        )

    def run_python_command(
        self,
        command: str,
        print_output: bool = True,
        colour: str = "light_yellow"
    ) -> str:
        """Run single-line python code, returning its output.

        Not suitable for code that contains double quotes.
        """
        python_command = "python -c \"" + command + "\""
        return self.run_shell_command(
            python_command,
            print_output=print_output, colour=colour
        )

    def run_python_code(
        self,
        code: str | list[str],
        print_output: bool = True,
        colour: str = "light_yellow"
    ) -> str:
        """Run any python code in the docker container, returning its output.

        Suitable for code that contains any quotes and escape characters.
        """
        if isinstance(code, list):
            # concatenate list elements into single string
            code = "\n".join(code)
        remote_tempfile = self.write_to_tempfile(code)
        return self.run_shell_command(
            f"/bin/python {remote_tempfile}",
            print_output=print_output, colour=colour
        )

    def _docker_swarm_connect(self) -> None:
        """Try to connect to this docker container via IPFS."""
        # Out of all our IPFS multi-addresses, choose the first non-localhost
        # IP address for both IPv4 & IPv6, and get the our multi_addresses for
        # those IP-addresses for both UDP & TCP
        multi_addresses = dict(ipfs_api.http_client.id())["Addresses"]
        ip6_tcp_maddr = [
            address
            for address in multi_addresses
            if address.startswith("/ip6/")
            and not address.startswith("/ip6/::1/")
            and address.split("/")[3] == "tcp"
        ]
        ip6_udp_maddr = [
            address
            for address in multi_addresses
            if address.startswith("/ip6/")
            and not address.startswith("/ip6/::1/")
            and address.split("/")[3] == "udp"
        ]
        ip4_tcp_maddr = [
            address
            for address in multi_addresses
            if address.startswith("/ip4/")
            and not address.startswith("/ip4/127.0.0.1/")
            and address.split("/")[3] == "tcp"
        ]
        ip4_udp_maddr = [
            address
            for address in multi_addresses
            if address.startswith("/ip4/")
            and not address.startswith("/ip4/127.0.0.1/")
            and address.split("/")[3] == "udp"
        ]
        commands = []
        if ip6_tcp_maddr:  # if any such addresses were found, try to connect
            commands.append(f"ipfs swarm connect {ip6_tcp_maddr[0]}")

        if ip6_udp_maddr:  # if any such addresses were found, try to connect
            commands.append(f"ipfs swarm connect {ip6_udp_maddr[0]}")

        if ip4_tcp_maddr:  # if any such addresses were found, try to connect
            commands.append(f"ipfs swarm connect {ip4_tcp_maddr[0]}")

        if ip4_udp_maddr:  # if any such addresses were found, try to connect
            commands.append(f"ipfs swarm connect {ip4_udp_maddr[0]}")

        self.run_bash_code(" & ".join(commands))

        # print(f"ipfs swarm connect {ip6_tcp_maddr}")
        # print(f"ipfs swarm connect {ip6_udp_maddr}")
        # print(f"ipfs swarm connect {ip4_tcp_maddr}")
        # print(f"ipfs swarm connect {ip4_udp_maddr}")


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
    docker_container.start(await_brenthy=False, await_ipfs=True)

    # Execute shell command on the container
    shell_output = docker_container.run_shell_command(
        "systemctl status brenthy")
    print("Output of Shell command:", shell_output)

    # Execute Python command on the container
    python_output = docker_container.run_python_command(
        "import walytis_beta_api;print(walytis_beta_api.get_walytis_beta_version())")
    print("Output of Python command:", python_output)

    docker_container.transfer_file("walytis_auth_docker.py", "/tmp/test/wad.py")
    docker_container.transfer_file("walytis_auth_docker.py", "/tmp/test/wad.py")
    docker_container.run_shell_command("ls /tmp/test/")

    remote_tempfile = docker_container.write_to_tempfile("Hello there!")
    docker_container.run_shell_command(f"cat {remote_tempfile}")
    # Stop the container
    docker_container.stop()
