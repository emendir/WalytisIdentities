FROM ubuntu:latest AS liboqs_build

RUN apt update && apt install -y build-essential git python3-dev cmake libssl-dev

RUN export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib && cd $(mktemp -d) && git clone --depth=1 https://github.com/open-quantum-safe/liboqs && cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && cmake --build liboqs/build --parallel 8 && cmake --build liboqs/build --target install


FROM local/brenthy_testing:latest AS walytis_installation
COPY --from=liboqs_build /usr/local/lib/liboqs* /usr/local/lib
WORKDIR /opt/walytis_identities


RUN apt-get install -y iputils-ping rsync sudo

COPY . /opt/walytis_identities
RUN pip install --break-system-packages --root-user-action ignore -r /opt/walytis_identities/requirements-dev.txt
RUN pip install --break-system-packages --root-user-action ignore -r /opt/walytis_identities/requirements.txt
RUN pip install --break-system-packages --root-user-action ignore -e /opt/walytis_identities/

RUN for python_package in /opt/walytis_identities/tests/walid_docker/python_packages/*; do [ -e "$python_package" ] || continue; pip install --break-system-packages --root-user-action ignore "$python_package"; done

# RUN pip show walytis_identities
## Run with:
# docker run -it --privileged local/walid_testing
