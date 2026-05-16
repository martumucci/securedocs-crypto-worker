import socket
import urllib.request
from http.client import HTTPConnection

import pytest

from securedocs_worker.health import start_health_server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def health_port() -> int:
    port = _free_port()
    server = start_health_server(port)
    yield port
    server.shutdown()


def test_health_endpoint_returns_200_ok(health_port: int) -> None:
    with urllib.request.urlopen(f"http://localhost:{health_port}/health") as response:
        assert response.status == 200
        assert response.read() == b"ok"


def test_unknown_path_returns_404(health_port: int) -> None:
    conn = HTTPConnection("localhost", health_port)
    conn.request("GET", "/not-here")
    response = conn.getresponse()

    assert response.status == 404
    conn.close()
