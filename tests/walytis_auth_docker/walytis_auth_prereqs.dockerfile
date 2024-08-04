FROM local/brenthy_testing:latest
WORKDIR /opt/WalytisAuth
COPY . /opt/WalytisAuth

COPY tests/walytis_auth_docker/IPFS-Monitoring /opt/IPFS-Monitor
# run installer except for its last line, removing all use of `sudo`
RUN head -n -1 /opt/IPFS-Monitor/install_linux_systemd.sh | sed 's/sudo //g' | bash


RUN mkdir /opt/MultiCrypt
COPY tests/walytis_auth_docker/MultiCrypt /opt/MultiCrypt
RUN pip install --root-user-action ignore /opt/MultiCrypt

COPY tests/walytis_auth_docker/IPFS-Toolkit /opt/IPFS-Toolkit
RUN pip install --root-user-action ignore /opt/IPFS-Toolkit

COPY tests/walytis_auth_docker/Walytis_Beta /opt/Walytis_Beta
RUN pip install --root-user-action ignore /opt/Walytis_Beta



RUN pip install --root-user-action ignore -r /opt/WalytisAuth/requirements-dev.txt
RUN pip install --root-user-action ignore -r /opt/WalytisAuth/requirements.txt

# RUN pip show walytis_auth
## Run with:
# docker run -it --privileged local/walytis_auth_testing