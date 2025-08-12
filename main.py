import socket
import time

from utils3 import runAsThread

class AuditServer:
    def __init__(self, host='localhost', port=9324):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        print(f"Audit server started on {self.host}:{self.port}")
        self._start_server()
        self._full_audit_trails = []

    @runAsThread
    def _start_server(self):
        while True:
            self.server_socket.listen()
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr} has been established.")
            self.handle_client(client_socket)

    @runAsThread
    def handle_client(self, client_socket):
        with client_socket:
            while True:
                data = client_socket.recv(1024)
                if data == b"dump_audit_trails":
                    self.dump_audit_trails()
                    client_socket.sendall(b"Audit trails dumped")
                    continue

                if not data:
                    break
                self._full_audit_trails.append(data.decode())
                print(f"Received data: {data.decode()}")
                client_socket.sendall(b"Data received")
            print("Client disconnected.")


    def dump_audit_trails(self):
        with open('audit_trails.txt', 'w') as f:
            for trail in self._full_audit_trails:
                f.write(trail + '\n')
        print("Audit trails dumped to audit_trails.txt")


if __name__ == '__main__':
    server = AuditServer()
    try:
        while True:
            i = input("Press enter to dump audit trails or Ctrl+C to exit: ")
            if i == '':
                server.dump_audit_trails()

    except KeyboardInterrupt:
        print("Shutting down server.")
        server.server_socket.close()
        print("Server closed.")