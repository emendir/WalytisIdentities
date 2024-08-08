FROM local/walytis_auth_prereqs:latest
WORKDIR /opt/WalIdentity
COPY . /opt/WalIdentity


# RUN pip install --root-user-action ignore --no-dependencies /opt/WalIdentity/

# RUN pip show WalIdentity
## Run with:
# docker run -it --privileged local/walytis_auth_testing