import datetime
import os
import sys
import threading
import time
import json
import pickle
import socket
import random
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
        self._write_lock = threading.Lock()
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

        except (pickle.UnpicklingError, EOFError):
            # NOTE: This is a recovery mechanism under the case that file corruption occurs from
            # mid-write crash or similar. The system does NOT provide backups or 'saves'.
            # if the .pickle file is corrupted externally (e.g. manual edit), recovery is not possible.
            # .tmp & recover is to cover this PROGRAM's write process only, and it's failure modes.
            # There are two scenarios:
            # 1. The .tmp file is corrupted - does not matter since we load from the main .pickle
            # 2. The main .pickle file is corrupted - we try to recover from the .tmp file
            # The .pickle file cannot be corrupted while .tmp is intact, because we write to .tmp first,
            # then rename to .pickle (atomic operation).

            # Note: This in prod has never been triggered on modern Unix-like systems. However, on
            # machines with SD cards or similar to write to .pickle often gets interrupted.
            # for large audit trails especially during power outages



            print(f"Failed to load audit trails from {pickle_location}. Searching for backup.")
            corrupt_file = pickle_location + '_{}.corrupt'.format(int(time.time()))
            os.rename(pickle_location, corrupt_file)
            print(f"Renamed corrupted file to {corrupt_file}")
            try:
                os.rename(pickle_location + '.tmp', pickle_location)
                self.load_audit_trails()
                os.remove(corrupt_file)
                print("Recovered from backup successfully.")
            except FileNotFoundError:
                raise RuntimeError('The main audit file is corrupted and no backup was found, the corrupted file has been renamed '
                                   'to .corrupt, on next-boot a new file will be created '
                                   'however any previously stored audit trails will be lost.')

            except Exception as e:
                print(f"Failed to recover from backup: {e}. Either delete the corrupt file or fix manually.")
                raise e


    def save_audit_trails(self):
        with self._write_lock:
            # ensure directory exists
            try:
                os.makedirs(os.path.dirname(pickle_location), exist_ok=True)
            except FileExistsError:
                pass
            payload = {
                'trails': self._full_audit_trails,
                'hosts': self._hosts,
            }

            # atomic write via 2-step process
            with open(pickle_location + '.tmp', 'wb') as f:
                pickle.dump(payload, f)
            os.rename(pickle_location + '.tmp', pickle_location)
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

                elif data == b'dump_compact':
                    self.dump_all_compact()
                    client_socket.sendall(b"Compact audit dump created")
                    continue
                elif data.decode().startswith('dump_compact_with_filter:'):
                    proj_filters = data.decode().split(':', 1)[1].split(',')
                    proj_filters = [p.strip() for p in proj_filters if p.strip()]
                    self.dump_all_compact(project_filters=proj_filters)
                    client_socket.sendall(b"Compact audit dump with filters created")
                    continue
                elif data == b'available_projects':
                    projects_avail = self.available_projects
                    response = json.dumps(projects_avail).encode()
                    client_socket.sendall(response)
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

    @staticmethod
    def _fetch_from_host(host_server: str, timeout: float = 3.0):
        try:
            with socket.create_connection((host_server, 9631), timeout=timeout) as s:
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

    def prune_boots_from_logs(self):
        # remove all `boot` events from logs
        original_count = len(self._full_audit_trails)
        self._full_audit_trails = [trail for trail in self._full_audit_trails if trail.get('event_type') != 'boot']
        pruned_count = original_count - len(self._full_audit_trails)
        if pruned_count > 0:
            print(f"Pruned {pruned_count} boot events from audit trails.")
            self.save_audit_trails()
        else:
            print("No boot events found to prune.")

    def dump_all_compact(self, project_filters: list[str] = None):
        """
        Dump all audit trails in a txt based format much smaller than JSON and automatically
        formatted for human reading.

        :arg project_filters: If provided, only dump these projects (list of project names)
        :return:
        """
        projects = {}
        for trail in self._full_audit_trails:
            project_name = trail.get('project_name', 'unknown_project')
            if project_filters and project_name not in project_filters:
                continue
            if project_name not in projects:
                projects[project_name] = []
            projects[project_name].append(trail)

        full_txt = "AUDIT SERVER COMPACT DUMP ({})\n".format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


        for project, trails in projects.items():
            sorted_trails = sorted(trails, key=lambda x: x.get('timestamp', 0))
            full_txt += "=" * 40 + "\n"
            full_txt += f"Project: {project}\n"
            full_txt += "-" * 40 + "\n"
            for trail in sorted_trails:
                full_txt += "\n"
                for key, value in trail.items():
                    if key == 'timestamp':
                        value = datetime.datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
                    full_txt += f"{key}: {value}\n"

        with open('compact_audit_dump.txt', 'w', encoding='utf-8') as f:
            f.write(full_txt)
        
        if project_filters:
            print(f"Compact audit dump created with {len(projects)} filtered project(s): {', '.join(projects.keys())}")
        else:
            print(f"Compact audit dump created with all {len(projects)} project(s): {', '.join(projects.keys())}")
        print("Output saved to: compact_audit_dump.txt")

    @property
    def available_projects(self):
        projects = set()
        for trail in self._full_audit_trails:
            project_name = trail.get('project_name', 'unknown_project')
            projects.add(project_name)
        return list(projects)





if __name__ == '__main__':
    args = sys.argv[1:]
    if '-build' in args:
        AuditServer.build_audit_server()
    else:
        server = AuditServer()
        try:
            print("Interactive commands: press Enter to dump today's trails.")
            msg = "Other commands: help | add <host> | remove <host> | list | fetch | dump_all | compact_dump | compact_dump <filters> | prune | exit"
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

                    # list all available projects
                    projects = server.available_projects
                    if projects:
                        print("Available projects in audit trails:")
                        for p in projects:
                            print(f" - {p}")
                    continue
                if i.lower() == 'fetch':
                    results = server.fetch_remote_audits()
                    print(json.dumps(results, indent=2))
                    continue

                if i.lower() == 'prune':
                    server.prune_boots_from_logs()
                    continue

                if i.lower() == 'compact_dump':
                    server.dump_all_compact()
                    continue
                
                if i.lower().startswith('compact_dump '):
                    filter_part = i[13:].strip()  # Remove 'compact_dump ' prefix
                    if filter_part:
                        # Parse filters - split by comma or space
                        filters = [f.strip() for f in filter_part.split(',') if f.strip()]
                        server.dump_all_compact(project_filters=filters)
                        print(f"Compact dump created with filters: {', '.join(filters)}")
                    else:
                        server.dump_all_compact()
                    continue

                if i.lower() in ('exit', 'quit', 'q'):
                    break
                print("Unknown command. Type 'help' for options.")

        except KeyboardInterrupt:
            print("Shutting down server.")
        finally:
            server.server_socket.close()
            print("Server closed.")
