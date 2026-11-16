#!/usr/bin/env bash
# Start TESP's services for the adapter: MongoDB, and with --pulsar a Pulsar
# REST server. Loopback ports; container names tes-authz-tesp-*.
# Remove them with tes/tesp/down.sh.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mongo_port="${TES_AUTHZ_TESP_MONGO_PORT:-18303}"
pulsar_port="${TES_AUTHZ_TESP_PULSAR_PORT:-18304}"

docker run -d --name tes-authz-tesp-mongo -p "127.0.0.1:${mongo_port}:27017" \
  --read-only --tmpfs /data/db --tmpfs /data/configdb --tmpfs /tmp \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --security-opt no-new-privileges \
  mongo:7.0.14 >/dev/null

if [[ "${1:-}" == "--pulsar" ]]; then
  docker build -q -t tes-authz-tesp-pulsar "$here/pulsar" >/dev/null
  docker run -d --name tes-authz-tesp-pulsar -p "127.0.0.1:${pulsar_port}:8913" \
    --cap-drop ALL --security-opt no-new-privileges tes-authz-tesp-pulsar >/dev/null
  echo "export TES_AUTHZ_TESP_PULSAR=http://127.0.0.1:${pulsar_port}"
fi
