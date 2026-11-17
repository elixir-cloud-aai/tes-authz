"""Test cases of the rules in `tes-authz.yml` (`semgrep --test`).

The cases contain findings on purpose; the file is never run.
"""

import http.client
import logging
import sys
import urllib.request
from urllib.request import urlopen

import yaml
from yaml import full_load as yaml_full_load

from common import encode_id, hash_id

URL = "http://opa:8181/v1/data/tes/authz/allow"
MAX_BODY_BYTES = 1024
log = logging.getLogger(__name__)

# urlopen-without-timeout

# ruleid: urlopen-without-timeout
urllib.request.urlopen(URL)
# ruleid: urlopen-without-timeout
urllib.request.urlopen(URL, b"{}")
# ruleid: urlopen-without-timeout
urlopen(URL)
# ruleid: urlopen-without-timeout
with urllib.request.urlopen(URL) as response:
    response.read()
# ruleid: urlopen-without-timeout
http.client.HTTPConnection("opa", 8181)
# ruleid: urlopen-without-timeout
http.client.HTTPSConnection("opa")
# ruleid: urlopen-without-timeout
urllib.request.urlopen(URL, timeout=None)
# ruleid: urlopen-without-timeout
http.client.HTTPConnection("opa", timeout=None)
opener = urllib.request.build_opener()
# ruleid: urlopen-without-timeout
opener.open(URL)
# ruleid: urlopen-without-timeout
opener.open(URL, b"{}", None)
# ruleid: urlopen-without-timeout
urllib.request.urlopen(URL, b"{}", None)
# ruleid: urlopen-without-timeout
http.client.HTTPConnection("opa", 8181, None)
# ok: urlopen-without-timeout
http.client.HTTPConnection("opa", 8181, 1.5)
# ok: urlopen-without-timeout
opener.open(URL, timeout=1.5)
# ok: urlopen-without-timeout
opener.open(URL, b"{}", 1.5)
# ok: urlopen-without-timeout
urllib.request.urlopen(URL, timeout=1.5)
# ok: urlopen-without-timeout
urllib.request.urlopen(URL, b"{}", 1.5)
# ok: urlopen-without-timeout
urlopen(URL, timeout=1.5)
# ok: urlopen-without-timeout
http.client.HTTPConnection("opa", 8181, timeout=1.5)
# ok: urlopen-without-timeout
http.client.HTTPSConnection("opa", timeout=1.5)


# request-body-unbounded


class UnboundedHandler:
    """Handlers that read request bodies without a bound."""

    def read_all(self) -> bytes:
        """Read up to the end of the stream."""
        # ruleid: request-body-unbounded
        return self.rfile.read()

    def read_negative(self) -> bytes:
        """Read up to the end of the stream, explicitly."""
        # ruleid: request-body-unbounded
        return self.rfile.read(-1)

    def read_declared(self) -> bytes:
        """Read as much as the client declares."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        # ruleid: request-body-unbounded
        return self.rfile.read(length) if length > 0 else b""

    def read_inline(self) -> bytes:
        """Read as much as the client declares, inline."""
        # ruleid: request-body-unbounded
        return self.rfile.read(int(self.headers["Content-Length"]))

    def read_if_positive(self) -> bytes:
        """Compare only with zero."""
        length = int(self.headers["Content-Length"])
        if length > 0:
            # ruleid: request-body-unbounded
            return self.rfile.read(length)
        return b""

    def read_lower_bound_only(self) -> bytes:
        """Check only that the length is not negative."""
        length = int(self.headers["Content-Length"])
        if length < 0:
            raise ValueError("bad length")
        # ruleid: request-body-unbounded
        return self.rfile.read(length)


class BoundedHandler:
    """Handlers that bound request bodies."""

    def read_checked(self) -> bytes:
        """Answer an error for long bodies, as the shims do."""
        length = int(self.headers["Content-Length"])
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413)
            return b""
        try:
            # ok: request-body-unbounded
            return self.rfile.read(length)
        finally:
            self.close_connection = True

    def read_raised(self) -> bytes:
        """Raise for long bodies, as the mock OIDC issuer does."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY_BYTES:
            raise ValueError("body too large")
        # ok: request-body-unbounded
        return self.rfile.read(length) if length > 0 else b""

    def read_reversed(self) -> bytes:
        """Compare the other way round."""
        length = int(self.headers["Content-Length"])
        if MAX_BODY_BYTES < length:
            raise ValueError("body too large")
        # ok: request-body-unbounded
        return self.rfile.read(length)

    def read_at_least(self) -> bytes:
        """Compare with a non-strict bound."""
        length = int(self.headers["Content-Length"])
        if length >= MAX_BODY_BYTES:
            raise ValueError("body too large")
        # ok: request-body-unbounded
        return self.rfile.read(length)

    def read_min(self) -> bytes:
        """Read at most the maximum."""
        length = int(self.headers["Content-Length"])
        # ok: request-body-unbounded
        return self.rfile.read(min(length, MAX_BODY_BYTES))


# credentials-or-subject-logged


def log_tokens(auth_token: str, jwt: str, raw_bearer: str, tokens: list[str]) -> None:
    """Log values named as tokens."""
    # ruleid: credentials-or-subject-logged
    log.info("token=%s", auth_token)
    # ruleid: credentials-or-subject-logged
    log.info("token=%s", jwt)
    # ruleid: credentials-or-subject-logged
    log.info("token=%s", raw_bearer)
    # ok: credentials-or-subject-logged
    log.info("%d tokens", len(tokens))


def log_requests(headers: dict[str, str], req: dict[str, dict[str, str]], token: str, request_id: str) -> None:
    """Log parts of a request."""
    # ruleid: credentials-or-subject-logged
    log.info("authorization=%s", headers.get("Authorization"))
    # ruleid: credentials-or-subject-logged
    log.debug("authorization=%s", headers["authorization"])
    header = headers.get("Authorization", "")
    bearer = header.removeprefix("Bearer ")
    # ruleid: credentials-or-subject-logged
    log.warning("token %s rejected", bearer)
    # ruleid: credentials-or-subject-logged
    log.error(f"token {token} rejected")
    # ruleid: credentials-or-subject-logged
    log.info("subject=%s", req["subject"])
    subject = req.get("subject", {})
    # ruleid: credentials-or-subject-logged
    log.info("claims=%s", subject["properties"])
    # ruleid: credentials-or-subject-logged
    log.critical("subject=%s", req["subject"]["id"])
    # ruleid: credentials-or-subject-logged
    log.log(logging.INFO, "subject=%s", subject)
    # ruleid: credentials-or-subject-logged
    print(req["subject"])
    # ruleid: credentials-or-subject-logged
    sys.stderr.write(bearer)
    # ok: credentials-or-subject-logged
    log.info("decision action=%s request_id=%s", req["action"]["name"], request_id)
    # ok: credentials-or-subject-logged
    log.info("subject=%s", hash_id(req["subject"]["id"]))
    # ruleid: credentials-or-subject-logged
    log.info("subject=%s", encode_id(subject["id"]))
    # ok: credentials-or-subject-logged
    log.info("authorization present=%s", "Authorization" in headers)


class LoggingHandler:
    """A handler that logs with the methods of `http.server`."""

    def log_requests(self) -> None:
        """Log parts of a request to stderr."""
        # ruleid: credentials-or-subject-logged
        self.log_message("authorization=%s", self.headers.get("Authorization"))
        # ruleid: credentials-or-subject-logged
        self.log_error("authorization=%s", self.headers["Authorization"])
        # ok: credentials-or-subject-logged
        self.log_message("%s %s", self.command, self.path)


# yaml-unsafe-load (as in trs-filer and FOCA)

# ruleid: yaml-unsafe-load
yaml.unsafe_load("a: 1")
# ruleid: yaml-unsafe-load
yaml.full_load("a: 1")
# ruleid: yaml-unsafe-load
yaml_full_load("a: 1")
# ruleid: yaml-unsafe-load
yaml.unsafe_load_all("a: 1")
# ruleid: yaml-unsafe-load
yaml.full_load_all("a: 1")
# ruleid: yaml-unsafe-load
yaml.load_all("a: 1", Loader=yaml.UnsafeLoader)
# ruleid: yaml-unsafe-load
yaml.load_all("a: 1", Loader=yaml.FullLoader)
# ruleid: yaml-unsafe-load
yaml.load_all("a: 1", Loader=yaml.Loader)
# ruleid: yaml-unsafe-load
yaml.load_all("a: 1", Loader=yaml.CUnsafeLoader)
# ruleid: yaml-unsafe-load
yaml.load_all("a: 1", yaml.FullLoader)
# ok: yaml-unsafe-load
yaml.safe_load("a: 1")
# ok: yaml-unsafe-load
yaml.load_all("a: 1", Loader=yaml.SafeLoader)
# ok: yaml-unsafe-load
yaml.load_all("a: 1", yaml.CSafeLoader)
