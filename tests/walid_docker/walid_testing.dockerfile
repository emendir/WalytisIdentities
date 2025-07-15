FROM local/walid_prereqs:latest
WORKDIR /opt/walytis_identities
COPY . /opt/walytis_identities
# RUN systemctl disable ipfs ipfs_router_mercy ipfs-monitor ipfs-init brenthy
# RUN pip install --root-user-action ignore --no-dependencies /opt/walytis_identities/
RUN rm *.log || true
# RUN pip show walytis_identities
## Run with:
# docker run -it --privileged local/walid_testing