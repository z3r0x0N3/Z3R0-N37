
import socket
import threading
from typing import Callable, List, Tuple


class Server:
    """Basic TCP server with pluggable handler."""

    def __init__(self, host: str, port: int, handler: Callable[[bytes], bytes]):
        self.host = host
        self.port = port
        self.handler = handler

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)

        self.running = False
        self._client_threads: List[threading.Thread] = []

    def serve_forever(self) -> None:
        self.server_socket.bind((self.host, self.port))
        self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(16)
        self.running = True
        print(f"Server listening on {self.host}:{self.port}")

        try:
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                client_thread.start()
                self._client_threads.append(client_thread)
        finally:
            self.running = False
            self.server_socket.close()

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        print(f"Accepted connection from {addr}")
        with conn:
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    response = self.handler(data)
                    conn.sendall(response)
                except OSError:
                    break

    def stop(self) -> None:
        self.running = False
        try:
            self.server_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.server_socket.close()
        for thread in self._client_threads:
            thread.join(timeout=1)
