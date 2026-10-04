import subprocess
import pytest


def _sh(cmd, cwd):
    subprocess.run(cmd, shell=True, cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    _sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 90 '
        '-subj "/CN=TestCA" -addext "basicConstraints=critical,CA:TRUE" '
        '-addext "keyUsage=critical,keyCertSign,cRLSign"', d)
    _sh('openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost"', d)
    (d / "ext.cnf").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
    _sh("openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial "
        "-out srv.pem -days 90 -extfile ext.cnf", d)
    _sh("openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial "
        "-out short.pem -days 2 -extfile ext.cnf", d)
    return d
