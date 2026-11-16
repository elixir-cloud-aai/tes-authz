# mypy: ignore-errors
"""A minimal OIDC issuer for the TESP adapter: discovery, JWKS and a mint endpoint.

TODO(phase2/oidc): replace with the shared mock OIDC issuer once that branch is
merged. Until then this runs with TESP's own interpreter (it needs PyJWT and
``cryptography``, which TESP depends on), so the harness stays standard-library
only. Test-only: ``POST /_mint`` signs whatever claims it is given.

Usage: ``python issuer.py <port>``
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "tes-authz-tesp"


class Handler(BaseHTTPRequestHandler):
    """Discovery, JWKS and minting."""

    def log_message(self, *args: object) -> None:
        """Stay quiet."""

    def _issuer(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def _send(self, status: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        """Serve discovery and the JWKS."""
        if self.path == "/.well-known/openid-configuration":
            return self._send(200, {"issuer": self._issuer(), "jwks_uri": self._issuer() + "/jwks"})
        if self.path == "/jwks":
            public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
            public.update({"kid": KID, "use": "sig", "alg": "RS256"})
            return self._send(200, {"keys": [public]})
        return self._send(404, {})

    def do_POST(self) -> None:  # noqa: N802
        """Sign the posted claims as an RS256 JWT."""
        if self.path != "/_mint":
            return self._send(404, {})
        claims = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        return self._send(200, {"token": jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
