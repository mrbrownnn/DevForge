"""A throwaway static server, so the clone loop can actually close.

Visual verification needs a candidate URL. For a static reproduction the honest
options were "make the operator run a dev server and hardcode the port" or "serve
the build ourselves". This does the second: an ephemeral port on 127.0.0.1, one
directory, for the length of one comparison.

Deliberate limits:

* **Loopback only.** Bound to ``127.0.0.1``, never ``0.0.0.0``. The build under
  test is not published to the network.
* **Ephemeral port.** Port 0, so nothing collides and nothing is predictable.
* **One directory, read only.** ``SimpleHTTPRequestHandler`` rooted at the given
  directory, which resolves symlinks to keep serving inside it.
* **Silent.** The default handler logs every request to stderr and would drown the
  run's own structured output.

This is a verification fixture, not a web server. It is not hardened for anything
else and nothing else should use it.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"


class _QuietHandler(SimpleHTTPRequestHandler):
    """Serves one directory and says nothing about it."""

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        return


@contextmanager
def static_site(directory: Path) -> Iterator[str]:
    """Serve ``directory`` on loopback for the duration of the block.

    Yields the base URL. The server is shut down and joined on exit, including when
    the block raises - a leaked thread here would outlive the run.
    """
    root = Path(directory).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"cannot serve {root}: not a directory")

    handler = partial(_QuietHandler, directory=str(root))
    server = ThreadingHTTPServer((HOST, 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="devforge-static", daemon=True)
    thread.start()
    try:
        yield f"http://{HOST}:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
