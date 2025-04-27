FROM local/walytis_auth_prereqs:latest
WORKDIR /opt/WalIdentity
COPY . /opt/WalIdentity
RUN touch /opt/we_are_in_docker
# RUN systemctl disable ipfs ipfs_router_mercy ipfs-monitor ipfs-init brenthy
# RUN pip install --root-user-action ignore --no-dependencies /opt/WalIdentity/

# RUN pip show WalIdentity
## Run with:
# docker run -it --privileged local/walytis_auth_testing