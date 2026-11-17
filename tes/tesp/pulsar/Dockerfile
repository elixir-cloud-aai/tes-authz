# A slim Pulsar REST server for the TESP smoke run. Unlike TESP's own
# docker/pulsar_rest image it has no container runtime, so jobs it receives
# fail; the smoke run checks AuthZ only, not execution.
FROM python:3.10.22-slim
RUN pip install --no-cache-dir 'pulsar-app[web]==0.15.6' \
    && useradd -m pulsar
USER pulsar
WORKDIR /home/pulsar
RUN pulsar-config --host 0.0.0.0
EXPOSE 8913
CMD ["pulsar"]
