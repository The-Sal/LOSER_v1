import sys
import time
import json
import pickle
import socket
import random
import os
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
        self._hosts: list[str] = []
        self.load_audit_trails()
        print(f"Loaded {len(self._full_audit_trails)} audit trails from {pickle_location}")
        print(f"Loaded {len(self._hosts)} managed host(s) from {pickle_location}")
        print("Audit server is ready to receive data. Build ID:", BUILD_IDENTIFIER)


    def load_audit_trails(self):
        try:
            with open(pickle_location, 'rb') as f:
                data = pickle.load(f)
                # Backward compatibility: older versions stored just a list of trails
                if isinstance(data, list):
                    self._full_audit_trails = data
                    self._hosts = []
                elif isinstance(data, dict):
                    self._full_audit_trails = data.get('trails', [])
                    self._hosts = data.get('hosts', [])
                else:
                    self._full_audit_trails = []
                    self._hosts = []
        except FileNotFoundError:
            print(f"No audit trails found at {pickle_location}. Starting fresh.")
            self._full_audit_trails = []
            self._hosts = []

    def save_audit_trails(self):
        # ensure directory exists
        try:
            os.makedirs(os.path.dirname(pickle_location), exist_ok=True)
        except Exception:
            pass
        payload = {
            'trails': self._full_audit_trails,
            'hosts': self._hosts,
        }
        with open(pickle_location, 'wb') as f:
            pickle.dump(payload, f)
        print(f"Audit trails and hosts saved to {pickle_location}")

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
                elif data == b'dump_audit_trails_all':
                    self.dump_audit_trails(todayOnly=False)
                    client_socket.sendall(b"All audit trails dumped")
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


    def dump_audit_trails(self, todayOnly=True):
        dumpable_dictionary = {}
        for trail in self._full_audit_trails:
            project_name = trail['project_name']
            if project_name not in dumpable_dictionary:
                dumpable_dictionary[project_name] = []
            if todayOnly:
                trail_timestamp = trail['timestamp']  # unix timestamp
                diff_from_now = time.time() - trail_timestamp
                if diff_from_now > (30 * 60 * 60):  # 30hours for 1 day + overnight buffer
                    continue
            dumpable_dictionary[project_name].append(trail)

        dumpable_dictionary['external_hosts'] = self._hosts
        dumpable_dictionary['external_hosts_audit'] = self.fetch_remote_audits()

        print("Dumping audit trails:")
        with open("dumped_audit_trails.json", "w") as f:
            json.dump(dumpable_dictionary, f)
        print(f"Audit trails dumped to dumped_audit_trails.json with {len(dumpable_dictionary)} projects.")

    # --- Host management and remote fetch ---
    def add_host(self, host: str):
        host = host.strip()
        if not host:
            print("Empty host ignored")
            return
        if host not in self._hosts:
            self._hosts.append(host)
            self.save_audit_trails()
            print(f"Host added: {host}")
        else:
            print(f"Host already present: {host}")

    def remove_host(self, host: str):
        host = host.strip()
        if host in self._hosts:
            self._hosts.remove(host)
            self.save_audit_trails()
            print(f"Host removed: {host}")
        else:
            print(f"Host not found: {host}")

    def list_hosts(self):
        return list(self._hosts)

    def _fetch_from_host(self, host: str, timeout: float = 3.0):
        try:
            with socket.create_connection((host, 9631), timeout=timeout) as s:
                s.sendall(b'audit')
                # Read the 4-byte big-endian length header
                header = s.recv(4)
                if len(header) < 4:
                    return "unable to reach"
                size = int.from_bytes(header, 'big')
                if size <= 0:
                    return "unable to reach"
                chunks = []
                remaining = size
                while remaining > 0:
                    chunk = s.recv(min(4096, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if remaining != 0:
                    return "unable to reach"
                data = b''.join(chunks)
                try:
                    return json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    return "unable to reach"
        except Exception as e:
            _ = e
            return "unable to reach"

    def fetch_remote_audits(self, timeout: float = 3.0):
        results = {}
        for host in self._hosts:
            results[host] = self._fetch_from_host(host, timeout=timeout)
        return results

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
            print("Interactive commands: press Enter to dump today's trails.")
            msg = "Other commands: help | add <host> | remove <host> | list | fetch | dump_all | exit"
            print(msg)
            while True:
                i = input("> ").strip()
                if i == '':
                    server.dump_audit_trails()
                    continue
                if i.lower() in ('help', 'h', '?'):
                    print(msg)
                    continue
                if i.lower() == 'dump_all':
                    server.dump_audit_trails(todayOnly=False)
                    continue
                if i.lower().startswith('add '):
                    host = i[4:].strip()
                    server.add_host(host)
                    continue
                if i.lower().startswith('remove '):
                    host = i[7:].strip()
                    server.remove_host(host)
                    continue
                if i.lower() == 'list':
                    hosts = server.list_hosts()
                    if hosts:
                        print("Managed hosts:")
                        for h in hosts:
                            print(f" - {h}")
                    else:
                        print("No managed hosts.")
                    continue
                if i.lower() == 'fetch':
                    results = server.fetch_remote_audits()
                    print(json.dumps(results, indent=2))
                    continue
                if i.lower() in ('exit', 'quit', 'q'):
                    break
                print("Unknown command. Type 'help' for options.")

        except KeyboardInterrupt:
            print("Shutting down server.")
        finally:
            server.server_socket.close()
            print("Server closed.")
