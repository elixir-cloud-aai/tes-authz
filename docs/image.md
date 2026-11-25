# Container image

The image `docker.io/elixircloud/tes-authz` is the OPA reference decision service in one container: OPA, the AuthZEN front (`shims/opa_front.py`) and the reference policy (`engines/opa/policy/`) of the release it is built from. It holds no policy data and no settings: you mount your copy of the policy data and set the rest in the environment. It is meant to run next to a TES, e.g. as a sidecar of the TES API pod, or on its own, like the [Kubernetes manifest](operators.md#kubernetes).

Releases tag the image with the version (`0.2.0`, no `v`), sign it and attest its build provenance; nothing is tagged `latest`. The policy in an image is that of its release, so a new policy means a new image. Until the first release, build it from a checkout: `docker build -t tes-authz .`.

## What runs

The entry point (`shims/opa_service.py`) checks that the policy data is a JSON object, starts OPA with the policy of the image and that data, waits until OPA is healthy, and then serves the front:

| Port | What | Reachable |
|---|---|---|
| 8080 (`TES_AUTHZ_PORT`) | AuthZEN front: `POST /access/v1/evaluation`, `GET /.well-known/authzen-configuration`, `GET /health` | on `TES_AUTHZ_HOST` (default all interfaces) |
| 8181 (`TES_AUTHZ_OPA_PORT`) | OPA's Data API (unauthenticated) | the container's loopback only |

If OPA exits, the service exits with status 1, so that the container is restarted. Unusable settings or policy data make it exit with status 2 before anything listens. `SIGTERM` stops both with status 0. The process runs as `nobody` (65534:65534), writes nothing (the root file system can be read-only) and needs no capabilities. The image has no pip.

## Run it

```sh
version=<version>
cp config/reference-policy.json policy-data.json   # from the checkout of that version; edit your groups
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/policy-data.json:/etc/tes-authz/data.json:ro" \
  "docker.io/elixircloud/tes-authz:$version"
curl -s http://127.0.0.1:8080/.well-known/authzen-configuration
```

The policy data follows the [reference policy](operators.md#reference-policy) of the same version: start from `config/reference-policy.json` of that release, not of another one.

## Settings

| Variable | Default | What |
|---|---|---|
| `TES_AUTHZ_DATA` | `/etc/tes-authz/data.json` | Policy data file (a JSON object), loaded as `data.tes_authz` whatever its name |
| `TES_AUTHZ_HOST` | `0.0.0.0` | Address of the front; `127.0.0.1` for a sidecar that only its own pod may reach |
| `TES_AUTHZ_PORT` | `8080` | Port of the front |
| `TES_AUTHZ_OPA_PORT` | `8181` | Loopback port of OPA; change it if the pod has another container on that port |
| `TES_AUTHZ_STARTUP_TIMEOUT` | `30` | Seconds to wait for OPA at start |
| `SHIM_BASE_URL` | `http://localhost:<port>` | Base URL advertised in `/.well-known/authzen-configuration`: the URL the TES uses |
| `SHIM_TIMEOUT` | `1.5` | Seconds the front waits for OPA per decision |
| `SHIM_MAX_BODY_BYTES` | `1048576` | Largest request body the front accepts |
| `SHIM_LOG_LEVEL` | `INFO` | Log level of the front |
| `TES_AUTHZ_POLICY` | `/opt/tes-authz/policy` | Policy directory; leave it, so that the image's policy is used |

## As a sidecar

In the pod of the TES API, the TES reaches the service on loopback, so no Service and no NetworkPolicy are needed for it:

```yaml
- name: tes-authz
  image: docker.io/elixircloud/tes-authz:<version>@sha256:<digest>
  env:
    - name: TES_AUTHZ_HOST
      value: 127.0.0.1
    - name: SHIM_BASE_URL
      value: http://127.0.0.1:8080
  # The front listens on loopback, where kubelet's HTTP probes can't reach
  # it: probe from inside the container
  readinessProbe:
    exec:
      command: [python, -c, "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities: {drop: [ALL]}
  volumeMounts:
    - name: tes-authz-data   # a ConfigMap with key data.json
      mountPath: /etc/tes-authz
      readOnly: true
```

The TES fails closed (503) while the service isn't ready. The TES's decision service URL is then `http://127.0.0.1:8080/access/v1/evaluation`. A change of the policy data takes effect when the container restarts (restart the pod after changing the ConfigMap).

## Verify an image

Each release image is signed with Sigstore (keyless, by the release workflow) and has a GitHub build provenance attestation:

```sh
image=docker.io/elixircloud/tes-authz:<version>
cosign verify "$image" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/elixir-cloud-aai/tes-authz/\.github/workflows/release\.yml@refs/tags/v'
gh attestation verify "oci://$image" --repo elixir-cloud-aai/tes-authz
```

Pin the digest that these commands verified in your deployment.
