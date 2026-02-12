FROM local/walid_prereqs:latest
WORKDIR /opt/walytis_identities
COPY ./src/ /opt/walytis_identities/src/
COPY ./tests/*.py /opt/walytis_identities/tests/
COPY ./tests/*.sh /opt/walytis_identities/tests/
COPY ./tests/*.tar /opt/walytis_identities/tests
COPY ./tests/walid_docker/ipfs_config.sh /opt/ipfs_config.sh
COPY ./tests/walid_docker/enable_ipfs_debug.sh /opt/enable_ipfs_debug.sh
COPY ./tests/cli_tools /opt/walytis_identities/tests/cli_tools

# RUN pip install --root-user-action ignore --no-dependencies /opt/walytis_identities/
RUN find /opt/ -type f -name "*.log" -exec rm -f {} + || true
RUN echo "" > ./tests/.walytis_identities.log
RUN /opt/enable_ipfs_debug.sh
## Run with:
# docker run -it --privileged local/walid_testing
