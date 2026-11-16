#!/usr/bin/env bash
# Remove the containers started by tes/tesp/up.sh (and its Pulsar image).
docker rm -f tes-authz-tesp-mongo tes-authz-tesp-pulsar >/dev/null 2>&1 || true
docker rmi tes-authz-tesp-pulsar >/dev/null 2>&1 || true
