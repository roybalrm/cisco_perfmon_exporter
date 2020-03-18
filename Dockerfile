FROM registry.fedoraproject.org/fedora:31

RUN dnf -y update; dnf -y install python3-click python3-twisted python3-lxml python3-pyyaml python3-prometheus_client; dnf -y clean all
RUN mkdir -p /app
WORKDIR /app
COPY perfmon.py /app
CMD [ "python3", "/app/perfmon.py", "/conf/config.yaml" ]
