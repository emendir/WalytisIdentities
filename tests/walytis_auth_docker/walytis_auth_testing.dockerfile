FROM local/walytis_auth_prereqs:latest
WORKDIR /opt/WalytisAuth
COPY . /opt/WalytisAuth


# RUN pip install --no-dependencies /opt/WalytisAuth/

# RUN pip show walytis_auth
## Run with:
# docker run -it --privileged local/walytis_auth_testing