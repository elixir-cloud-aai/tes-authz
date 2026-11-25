# The OPA reference decision service of tes-authzen in one image: OPA (the
# static binary of the official image), the AuthZEN front
# (`shims/opa_front.py`, `shims/common.py`) and the reference policy
# (`engines/opa/policy/`) of the commit it is built from, started by
# `shims/opa_service.py`. OPA listens on the container's loopback only and
# answers only the decision query and the health check
# (`engines/opa/system/authz.rego`); the front listens on port 8080. The
# policy DATA is not in the image: mount the operator's copy of
# `config/reference-policy.json` at `/etc/tes-authz/data.json` (or set
# `TES_AUTHZ_DATA`). See `docs/image.md`.
#
# The base images have the versions of `compose.yaml` (which the tests
# check), pinned by index digest (`docker buildx imagetools inspect
# <image>`, first `Digest:`); bump the versions together with
# `compose.yaml`. The digest of the Python image may be newer than the one
# in `deploy/kubernetes/tes-authz.yaml` (same tag, rebuilt with fixes).
# Accepted scan findings are in `.trivyignore.yaml`.

FROM docker.io/openpolicyagent/opa:1.22.4-static@sha256:12cecac5a174368f7d3f09d3a19d040ebe0c91d576e520335ae7a985a26e39d3 AS opa

FROM docker.io/library/python:3.15.1-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

# TEMPORARY, remove before the next release (D-435: no temporary apt fixes
# in release images). The Python image (digest above, checked 2026-11-25)
# still ships libzstd1 1.5.7+dfsg-1 (CVE-2026-124851, HIGH, fixed in
# 1.5.7+dfsg-1+deb13u1), which fails the image scan of every PR. Once
# upstream rebuilds the tag with the fix, bump the digest above and
# delete this step.
RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# The service is standard-library only: no installer in the image (pip
# would only widen what the image scan reports and what an attacker could
# use)
RUN python -m pip uninstall --yes --root-user-action=ignore pip \
    && ! python -c "import pip" 2>/dev/null

COPY --from=opa /opa /usr/local/bin/opa
COPY engines/opa/policy/ /opt/tes-authz/policy/
COPY engines/opa/system/ /opt/tes-authz/system/
COPY shims/common.py shims/opa_front.py shims/opa_service.py /opt/tes-authz/

# The policy is checked when the image is built, so that an image never
# ships a policy that OPA would refuse at start
RUN opa check --strict /opt/tes-authz/policy /opt/tes-authz/system

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/tes-authz \
    TES_AUTHZ_POLICY=/opt/tes-authz/policy \
    TES_AUTHZ_SYSTEM_POLICY=/opt/tes-authz/system \
    TES_AUTHZ_DATA=/etc/tes-authz/data.json

WORKDIR /opt/tes-authz
# nobody, as in `compose.yaml` and the Kubernetes manifest; numeric, so that
# `runAsNonRoot` can verify it
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["python", "/opt/tes-authz/opa_service.py"]
