#!/usr/bin/env bash
# Remove the TESK container and the kind cluster of tes/tesk/up.sh.
docker rm -f tes-authz-tesk-api >/dev/null 2>&1 || true
kind delete cluster --name tes-authz-tesk >/dev/null 2>&1 || true
