import sys
import json
import pickle
import socket
import random
import os.path
import subprocess
from utils3 import runAsThread, Container

# DO NOT MODIFY THE BELOW LINE
BUILD_IDENTIFIER = 'src.audit_server'
# DO NOT MODIFY THE ABOVE LINE

pickle_location = os.path.join(os.path.expanduser('~'), '.cellar/loser_audit.pickle')

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
        self.load_audit_trails()
        print(f"Loaded {len(self._full_audit_trails)} audit trails from {pickle_location}")
        print("Audit server is ready to receive data. Build ID:", BUILD_IDENTIFIER)


    def load_audit_trails(self):
        try:
            with open(pickle_location, 'rb') as f:
                self._full_audit_trails = pickle.load(f)
        except FileNotFoundError:
            print(f"No audit trails found at {pickle_location}. Starting fresh.")
            self._full_audit_trails = []

    def save_audit_trails(self):
        with open(pickle_location, 'wb') as f:
            pickle.dump(self._full_audit_trails, f)
        print(f"Audit trails saved to {pickle_location}")

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
                try:
                    self._full_audit_trails.append(json.loads(data.decode()))
                    self.save_audit_trails()
                except json.JSONDecodeError:
                    print("Received invalid JSON data.")
                    client_socket.sendall(b"Invalid JSON data received")
                    continue
                print(f"Received data: {data.decode()}")
                client_socket.sendall(b"Data received")
            print("Client disconnected.")


    def dump_audit_trails(self):
        dumpable_dictionary = {}
        for trail in self._full_audit_trails:
            project_name = trail['project_name']
            if project_name not in dumpable_dictionary:
                dumpable_dictionary[project_name] = []
            dumpable_dictionary[project_name].append(trail)

        print("Dumping audit trails:")
        with open("dumped_audit_trails.json", "w") as f:
            json.dump(dumpable_dictionary, f, indent=4)
        print(f"Audit trails dumped to dumped_audit_trails.json with {len(dumpable_dictionary)} projects.")

    @staticmethod
    def build_audit_server():
        fp = __file__
        if not os.path.exists(fp):
            raise FileNotFoundError(f"File {fp} does not exist.")


        store_dir = pickle_location.replace('loser_audit.pickle', 'audit_server')
        build_id = 'compiled.audit_server.{}'.format(random.randint(1000, 9999))

        print(f"Building audit server with build ID: {build_id}")

        with Container() as c:
            c.copyFile(src=fp)
            lines_of_old_file = open(fp, 'r').readlines()
            with open('main.py', 'w+') as f:
                for line in lines_of_old_file:
                    if line.strip() == "BUILD_IDENTIFIER = 'src.audit_server'":
                        f.write(f'BUILD_IDENTIFIER = "{build_id}"\n')
                    else:
                        f.write(line)


            build_proc = [
                'py', '-m', 'nuitka', 'main.py'
            ]
            print('Building audit server with command:', ' '.join(build_proc))
            subprocess.check_call(build_proc)
            subprocess.check_call(['mv', 'main.bin', store_dir])

        print(f"Audit server built and stored at {store_dir}")
        exit(0)




if __name__ == '__main__':
    args = sys.argv[1:]
    if '-build' in args:
        AuditServer.build_audit_server()
    else:
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
