FROM local/brenthy_testing:latest
WORKDIR /opt/WalIdentity
COPY . /opt/WalIdentity

COPY tests/walytis_auth_docker/IPFS-Monitoring /opt/IPFS-Monitor
RUN apt-get install -y iputils-ping rsync
# run installer except for its last line, removing all use of `sudo`
RUN cd /opt/IPFS-Monitor && head -n -1 /opt/IPFS-Monitor/install_linux_systemd.sh | sed 's/sudo //g' | bash

RUN pip install --break-system-packages --root-user-action ignore -r /opt/WalIdentity/requirements-dev.txt
RUN pip install --break-system-packages --root-user-action ignore -r /opt/WalIdentity/requirements.txt
RUN for SUBFOLDER in /opt/WalIdentity/tests/walytis_auth_docker/python_packages/*; do pip install --break-system-packages --root-user-action ignore "$SUBFOLDER"; done


# RUN pip show WalIdentity
## Run with:
# docker run -it --privileged local/walytis_auth_testing