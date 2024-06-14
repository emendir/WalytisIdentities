FROM local/brenthy_testing:latest
WORKDIR /opt/WalytisAuth
COPY . /opt/WalytisAuth

COPY tests/walytis_auth_docker/IPFS-Monitoring /opt/IPFS-Monitor
# run installer except for its last line, removing all use of `sudo`
RUN head -n -1 /opt/IPFS-Monitor/install_linux_systemd.sh | sed 's/sudo //g' | bash


RUN mkdir /opt/MultiCrypt
COPY tests/walytis_auth_docker/MultiCrypt /opt/MultiCrypt
RUN pip install /opt/MultiCrypt

COPY tests/walytis_auth_docker/IPFS-Toolkit /opt/IPFS-Toolkit
RUN pip install /opt/IPFS-Toolkit



RUN pip install -r /opt/WalytisAuth/dev-requirements.txt
RUN pip install /opt/WalytisAuth/

# RUN pip show walytis_auth
## Run with:
# docker run -it --privileged local/walytis_auth_testing