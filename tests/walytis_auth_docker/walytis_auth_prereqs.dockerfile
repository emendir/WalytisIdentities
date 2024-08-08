FROM local/brenthy_testing:latest
WORKDIR /opt/WalIdentity
COPY . /opt/WalIdentity

COPY tests/walytis_auth_docker/IPFS-Monitoring /opt/IPFS-Monitor
RUN apt-get install -y iputils-ping
# run installer except for its last line, removing all use of `sudo`
RUN cd /opt/IPFS-Monitor && head -n -1 /opt/IPFS-Monitor/install_linux_systemd.sh | sed 's/sudo //g' | bash

RUN mkdir /opt/MultiCrypt
COPY tests/walytis_auth_docker/MultiCrypt /opt/MultiCrypt
RUN pip install --root-user-action ignore /opt/MultiCrypt

COPY tests/walytis_auth_docker/IPFS-Toolkit /opt/IPFS-Toolkit
RUN pip install --root-user-action ignore /opt/IPFS-Toolkit

COPY tests/walytis_auth_docker/Walytis_Beta /opt/Walytis_Beta
RUN pip install --root-user-action ignore /opt/Walytis_Beta



RUN pip install --root-user-action ignore -r /opt/WalIdentity/requirements-dev.txt
RUN pip install --root-user-action ignore -r /opt/WalIdentity/requirements.txt

# RUN pip show WalIdentity
## Run with:
# docker run -it --privileged local/walytis_auth_testing