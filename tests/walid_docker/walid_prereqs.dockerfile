FROM local/brenthy_testing:latest
WORKDIR /opt/walytis_identities

# COPY tests/walid_docker/IPFS-Monitoring /opt/IPFS-Monitor
RUN apt-get install -y iputils-ping rsync
# run installer except for its last line, removing all use of `sudo`
# RUN cd /opt/IPFS-Monitor && head -n -1 /opt/IPFS-Monitor/install_linux_systemd.sh | sed 's/sudo //g' | bash

COPY . /opt/walytis_identities
RUN pip install --break-system-packages --root-user-action ignore -r /opt/walytis_identities/requirements-dev.txt
RUN pip install --break-system-packages --root-user-action ignore -r /opt/walytis_identities/requirements.txt
RUN pip install --break-system-packages --root-user-action ignore -e /opt/walytis_identities/

RUN for python_package in /opt/walytis_identities/tests/walid_docker/python_packages/*; do [ -e "$python_package" ] || continue; pip install --break-system-packages --root-user-action ignore "$python_package"; done

# RUN pip show walytis_identities
## Run with:
# docker run -it --privileged local/walid_testing