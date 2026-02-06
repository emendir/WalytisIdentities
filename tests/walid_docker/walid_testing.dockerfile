FROM local/walid_prereqs:latest
WORKDIR /opt/walytis_identities
COPY ./src/ /opt/walytis_identities/src/
COPY ./tests/*.py /opt/walytis_identities/tests/
COPY ./tests/*.sh /opt/walytis_identities/tests/
COPY ./tests/*.tar /opt/walytis_identities/tests
# RUN systemctl disable ipfs ipfs_router_mercy ipfs-monitor ipfs-init brenthy
# RUN pip install --root-user-action ignore --no-dependencies /opt/walytis_identities/
RUN find /opt/ -type f -name "*.log" -exec rm -f {} + || true
RUN echo "" > ./tests/.walytis_identities.log
# RUN pip show walytis_identities
## Run with:
# docker run -it --privileged local/walid_testing
