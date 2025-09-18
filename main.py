import sys
import os

# Force UTF-8 encoding for Nuitka builds
if hasattr(sys, 'frozen'):  # This is True when running as Nuitka executable
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Alternative: Set stdout encoding directly
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


import sys
import threading
import datetime
import time
import json
import pickle
import socket
import random
import subprocess
from utils3 import runAsThread, Container
from ic_audit.net_doc import NetworkDiagnostics

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

    def select_host_for_intensive_operation(self):
        """Select a host from the list for intensive operations like speedtest"""
        hosts = self.list_hosts()
        if not hosts:
            print("No managed hosts available.")
            return None
        if len(hosts) == 1:
            return hosts[0]

        print("Select a host for the intensive operation:")
        for i, host in enumerate(hosts, 1):
            print(f"{i}. {host}")

        while True:
            try:
                choice = input(f"Enter choice (1-{len(hosts)}): ").strip()
                if not choice:
                    return None
                idx = int(choice) - 1
                if 0 <= idx < len(hosts):
                    return hosts[idx]
                else:
                    print(f"Please enter a number between 1 and {len(hosts)}.")
            except (ValueError, KeyboardInterrupt):
                print("Invalid input or operation cancelled.")
                return None

    @staticmethod
    def _ping_host_timestamp(host_server: str, timeout: float = 3.0):
        """Ping the timestamp endpoint to measure round trip time"""
        try:
            start_time = time.time()
            with socket.create_connection((host_server, 9631), timeout=timeout) as s:
                s.sendall(b'timestamp')
                # Read the 4-byte big-endian length header
                header = s.recv(4)
                if len(header) < 4:
                    return {"error": "timestamp endpoint not available", "rtt_ms": None}
                size = int.from_bytes(header, 'big')
                if size <= 0:
                    return {"error": "timestamp endpoint not available", "rtt_ms": None}
                chunks = []
                remaining = size
                while remaining > 0:
                    chunk = s.recv(min(4096, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if remaining != 0:
                    return {"error": "timestamp endpoint not available", "rtt_ms": None}
                end_time = time.time()
                rtt_ms = (end_time - start_time) * 1000  # Convert to milliseconds

                data = b''.join(chunks)
                try:
                    remote_timestamp = float(data.decode('utf-8'))
                    return {"remote_timestamp": remote_timestamp, "rtt_ms": round(rtt_ms, 2)}
                except (ValueError, UnicodeDecodeError):
                    return {"error": "timestamp endpoint not available", "rtt_ms": None}
        except Exception as e:
            _ = e
            return {"error": "timestamp endpoint not available", "rtt_ms": None}

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

    @staticmethod
    def _fetch_speedtest_from_host(host_server: str, timeout: float = 120.0):
        """Fetch speedtest data from a remote host with extended timeout for intensive operation"""
        try:
            with socket.create_connection((host_server, 9631), timeout=timeout) as s:
                s.sendall(b'speedtest')
                # Read the 4-byte big-endian length header
                header = s.recv(4)
                if len(header) < 4:
                    return {"error": "speedtest endpoint not available"}
                size = int.from_bytes(header, 'big')
                if size <= 0:
                    return {"error": "speedtest endpoint not available"}
                chunks = []
                remaining = size
                while remaining > 0:
                    chunk = s.recv(min(4096, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if remaining != 0:
                    return {"error": "speedtest endpoint not available"}
                data = b''.join(chunks)
                try:
                    return json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    return {"error": "speedtest endpoint not available"}
        except Exception as e:
            return {"error": f"connection failed: {str(e)}"}

    def fetch_remote_audits(self, timeout: float = 3.0):
        results = {}
        for host in self._hosts:
            audit_result = self._fetch_from_host(host, timeout=timeout)
            ping_result = self._ping_host_timestamp(host, timeout=timeout)
            results[host] = {
                'audit': audit_result,
                'ping': ping_result
            }
        return results

    def perform_speedtest(self):
        """Perform speedtest on a selected host and optionally on local machine"""
        selected_host = self.select_host_for_intensive_operation()
        if not selected_host:
            return

        print(f"Running speedtest on {selected_host}...")
        remote_result = self._fetch_speedtest_from_host(selected_host)

        if 'error' in remote_result:
            print(f"Remote speedtest failed: {remote_result['error']}")
            return

        # Display remote speedtest results
        if remote_result.get('installed') and remote_result.get('result'):
            result = remote_result['result']
            print(f"\nSpeedtest results for {selected_host}:")
            print(f"ISP: {result.get('isp', 'Unknown')}")
            if 'download' in result:
                download_mbps = (result['download']['bandwidth'] * 8) / 1_000_000  # Convert to Mbps
                print(f"Download: {download_mbps:.2f} Mbps")
            if 'upload' in result:
                upload_mbps = (result['upload']['bandwidth'] * 8) / 1_000_000  # Convert to Mbps
                print(f"Upload: {upload_mbps:.2f} Mbps")
            if 'ping' in result:
                print(f"Ping: {result['ping']['latency']:.2f} ms")
        elif not remote_result.get('installed'):
            print(f"Speedtest is not installed on {selected_host}")
        else:
            print(f"Speedtest failed on {selected_host}")

    def diagnose_connection(self):
        """Diagnose connection issues between local machine and selected host"""
        selected_host = self.select_host_for_intensive_operation()
        if not selected_host:
            return

        print(f"Diagnosing connection between local machine and {selected_host}...")

        # Initialize local network diagnostics
        local_net_diag = NetworkDiagnostics()

        # Step 1: Check if local speedtest is available
        local_speedtest_installed = local_net_diag.speedtest_installed()

        # Step 2: Get remote speedtest data
        print("Fetching remote speedtest data...")
        remote_result = self._fetch_speedtest_from_host(selected_host)

        # Step 3: Get local speedtest data if available
        local_result = None
        if local_speedtest_installed:
            print("Running local speedtest...")
            try:
                local_result = local_net_diag.speedtest()
            except Exception as e:
                print(f"Local speedtest failed: {e}")

        # Step 4: Get ping data
        ping_result = self._ping_host_timestamp(selected_host)

        # Analysis and bottleneck detection
        print(f"\n=== DIAGNOSTIC REPORT for {selected_host} ===")

        # Collect all metrics for analysis
        rtt = ping_result.get('rtt_ms') if 'error' not in ping_result else None
        remote_download = 0
        remote_upload = 0
        local_download = 0
        local_upload = 0

        # Ping analysis
        if rtt is not None:
            if rtt < 50:
                print(f"✓ Network latency: {rtt}ms (Good)")
            elif rtt < 150:
                print(f"⚠ Network latency: {rtt}ms (Moderate - may affect performance)")
            else:
                print(f"✗ Network latency: {rtt}ms (HIGH - significant bottleneck)")
        else:
            print(f"✗ Network connectivity: {ping_result['error']}")

        # Remote speedtest analysis
        remote_has_data = False
        remote_network_fault = False
        if 'error' not in remote_result and remote_result.get('installed') and remote_result.get('result'):
            remote_data = remote_result['result']
            remote_download = (remote_data['download']['bandwidth'] * 8) / 1_000_000 if 'download' in remote_data else 0
            remote_upload = (remote_data['upload']['bandwidth'] * 8) / 1_000_000 if 'upload' in remote_data else 0
            print(f"✓ {selected_host} internet: ↓{remote_download:.1f}Mbps ↑{remote_upload:.1f}Mbps")
            remote_has_data = True
        elif not remote_result.get('installed'):
            print(f"⚠ {selected_host}: speedtest not installed (cannot measure internet speed)")
        elif remote_result.get('installed') and not remote_result.get('result'):
            # Speedtest is installed but failed to run - network fault
            print(f"🚨 {selected_host}: speedtest installed but FAILED to run")
            print(f"   → {selected_host} has a NETWORK FAULT")
            remote_network_fault = True
        else:
            print(f"✗ {selected_host} speedtest: {remote_result.get('error', 'Failed')}")

        # Local speedtest analysis
        local_has_data = False
        local_network_fault = False
        if local_speedtest_installed and local_result:
            local_download = (local_result['download']['bandwidth'] * 8) / 1_000_000 if 'download' in local_result else 0
            local_upload = (local_result['upload']['bandwidth'] * 8) / 1_000_000 if 'upload' in local_result else 0
            print(f"✓ Local machine internet: ↓{local_download:.1f}Mbps ↑{local_upload:.1f}Mbps")
            local_has_data = True
        elif not local_speedtest_installed:
            print("⚠ Local machine: speedtest not installed (cannot measure internet speed)")
        elif local_speedtest_installed and not local_result:
            # Speedtest is installed but failed to run - network fault
            print("🚨 Local machine: speedtest installed but FAILED to run")
            print("   → Local machine has a NETWORK FAULT")
            local_network_fault = True
        else:
            print("✗ Local machine speedtest: Failed")

        # BOTTLENECK ANALYSIS - Blame assignment
        print(f"\n🔍 BOTTLENECK ANALYSIS:")

        # Priority 1: Network connectivity issues
        if rtt is None:
            print(f"🚨 PRIMARY ISSUE: Network connectivity problem")
            print(f"   → Cannot reach {selected_host} - check network/firewall")

        # Priority 2: Network faults (speedtest installed but fails)
        elif local_network_fault and remote_network_fault:
            print(f"🚨 CRITICAL: Both machines have NETWORK FAULTS")
            print(f"   → Both {selected_host} and local machine have internet connectivity issues")
            print(f"   → Check ISP connections, DNS, firewalls on both machines")

        elif local_network_fault:
            print(f"🎯 BOTTLENECK IDENTIFIED: Local machine NETWORK FAULT")
            print(f"   → Local machine has speedtest installed but cannot reach internet")
            print(f"   → Check local ISP connection, DNS settings, firewall rules")

        elif remote_network_fault:
            print(f"🎯 BOTTLENECK IDENTIFIED: {selected_host} NETWORK FAULT")
            print(f"   → {selected_host} has speedtest installed but cannot reach internet")
            print(f"   → Check {selected_host} ISP connection, DNS settings, firewall rules")

        # Priority 3: High latency
        elif rtt > 150:
            print(f"🚨 PRIMARY BOTTLENECK: Network latency ({rtt}ms)")
            print(f"   → High latency between local machine and {selected_host}")
            print(f"   → This will slow down all communication regardless of internet speed")

        # Priority 4: Speed comparison analysis
        elif local_has_data and remote_has_data:
            # Both have speed data - detailed comparison
            speed_diff_threshold = 20  # Mbps

            if abs(local_download - remote_download) < speed_diff_threshold:
                print(f"✅ Both machines have similar internet speeds (~{(local_download + remote_download)/2:.0f}Mbps)")
                if min(local_download, remote_download) < 10:
                    print(f"⚠️  Both connections are slow - this is a shared bottleneck")
                else:
                    print(f"   → Internet speeds are adequate")

            elif local_download > remote_download + speed_diff_threshold:
                print(f"🎯 BOTTLENECK IDENTIFIED: {selected_host}")
                print(f"   → {selected_host} has slower internet ({remote_download:.1f}Mbps vs {local_download:.1f}Mbps locally)")
                print(f"   → {selected_host} is limiting overall performance")

            elif remote_download > local_download + speed_diff_threshold:
                print(f"🎯 BOTTLENECK IDENTIFIED: Local machine")
                print(f"   → Local internet is slower ({local_download:.1f}Mbps vs {remote_download:.1f}Mbps on {selected_host})")
                print(f"   → Local connection is limiting overall performance")

        elif local_has_data and not remote_has_data:
            print(f"🎯 BOTTLENECK IDENTIFIED: {selected_host}")
            print(f"   → Cannot measure {selected_host} internet speed")
            print(f"   → Local speed: {local_download:.1f}Mbps (measurable)")
            print(f"   → Issue likely on {selected_host} side")

        elif remote_has_data and not local_has_data:
            print(f"🎯 BOTTLENECK IDENTIFIED: Local machine")
            print(f"   → Cannot measure local internet speed")
            print(f"   → {selected_host} speed: {remote_download:.1f}Mbps (measurable)")
            print(f"   → Issue likely on local machine side")

        else:
            print(f"❓ INCONCLUSIVE: Cannot measure internet speeds on either machine")
            print(f"   → Install speedtest on both machines for detailed analysis")

        print("=== END DIAGNOSTIC REPORT ===\n")

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
                sys.executable, '-m', 'nuitka', 'main.py', '--follow-imports',
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

    # --- CLI-only utilities ---
    def interactive_remove_recent(self):
        """
        CLI-only: Show last up to 10 audit entries (most recent first), allow previewing an entry
        in detail by entering '?', then prompt to select one to remove and persist the change.
        Not exposed over the socket server.
        """
        total = len(self._full_audit_trails)
        if total == 0:
            print("No audit entries available to remove.")
            return
        n = min(10, total)
        recent = self._full_audit_trails[-n:]
        # Show newest first
        enumerated = list(enumerate(reversed(recent), start=1))
        print(f"Last {n} audit entries (most recent first):")
        for idx, trail in enumerated:
            ts = trail.get('timestamp')
            try:
                ts_h = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if isinstance(ts, (int, float)) else str(ts)
            except Exception as e:
                _ = e
                ts_h = str(ts)
            proj = trail.get('project_name', 'unknown_project')
            ev = trail.get('event_type', trail.get('event', ''))
            summary = trail.get('message') or trail.get('summary') or ''
            # Keep each line compact
            summary_str = (summary[:60] + '…') if isinstance(summary, str) and len(summary) > 60 else (summary or '')
            print(f" {idx:>2}. [{ts_h}] project={proj} event={ev} {summary_str}")

        def _global_index_for_selection(selection: int) -> int:
            # Map selection to global index: 1 means most recent -> last element
            return total - selection

        def _preview_one():
            # Ask user which one to preview, then show full details
            while True:
                choice_in = input(f"Preview which? Enter 1-{n} (or 'q' to go back): ").strip().lower()
                if choice_in in ('q', 'quit', 'exit', ''):
                    return
                if not choice_in.isdigit():
                    print("Please enter a number or 'q'.")
                    continue
                selec = int(choice_in)
                if not (1 <= selec <= n):
                    print(f"Please enter a number between 1 and {n}.")
                    continue
                gi = _global_index_for_selection(selec)
                trail_in = self._full_audit_trails[gi]
                print("\n=== Audit Entry Detail ===")
                try:
                    # Pretty JSON if possible
                    print(json.dumps(trail_in, indent=2, default=str))
                except Exception as en:
                    _ = en
                    # Fallback key-value lines
                    # noinspection all
                    for k, v in trail_in.items():
                        print(f"{k}: {v}")
                print("=== End Detail ===\n")
                # After showing once, return to main prompt
                return

        while True:
            choice = input(f"Select 1-{n} to remove, '?' to preview, or 'q' to cancel: ").strip().lower()
            if choice in ('q', 'quit', 'exit'):
                print("Cancelled. No changes made.")
                return
            if choice == '?':
                _preview_one()
                continue
            if not choice.isdigit():
                print("Please enter a number, '?' to preview, or 'q' to cancel.")
                continue
            sel = int(choice)
            if not (1 <= sel <= n):
                print(f"Please enter a number between 1 and {n}.")
                continue
            global_index = _global_index_for_selection(sel)
            to_delete = self._full_audit_trails[global_index]
            # Confirm with brief details
            ts = to_delete.get('timestamp')
            try:
                ts_h = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if isinstance(ts, (int, float)) else str(ts)
            except Exception as e:
                _ = e
                ts_h = str(ts)
            proj = to_delete.get('project_name', 'unknown_project')
            ev = to_delete.get('event_type', to_delete.get('event', ''))
            # Offer an extra quick preview before deletion
            confirm = input(f"Remove entry [{ts_h}] project={proj} event={ev}? (y/N, '?' to preview): ").strip().lower()
            if confirm == '?':
                # show full details then go back to main loop without deleting
                print("\n=== Audit Entry Detail ===")
                try:
                    print(json.dumps(to_delete, indent=2, default=str))
                except Exception as e:
                    _ = e
                    for k, v in to_delete.items():
                        print(f"{k}: {v}")
                print("=== End Detail ===\n")
                continue
            if confirm != 'y':
                print("Cancelled. No changes made.")
                return
            del self._full_audit_trails[global_index]
            self.save_audit_trails()
            print("Entry removed and saved.")
            return

def main():
    args = sys.argv[1:]
    if '-build' in args:
        AuditServer.build_audit_server()
    else:
        server = AuditServer()
        try:
            print("Interactive commands: press Enter to dump today's trails.")
            msg = "Other commands: help | add <host> | remove <host> | list | fetch | ping | speed | diagnostic | dump_all | compact_dump | compact_dump <filters> | prune | rm_last | exit"
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
                if i.lower() == 'ping':
                    hosts = server.list_hosts()
                    if not hosts:
                        print("No managed hosts to ping.")
                        continue
                    print("Pinging all managed hosts...")
                    for host in hosts:
                        # noinspection PyProtectedMember
                        ping_result = server._ping_host_timestamp(host)
                        if 'error' in ping_result:
                            print(f"{host}: {ping_result['error']}")
                        else:
                            print(f"{host}: {ping_result['rtt_ms']}ms RTT")
                    continue
                if i.lower() == 'speed':
                    server.perform_speedtest()
                    continue
                if i.lower() == 'diagnostic':
                    server.diagnose_connection()
                    continue

                if i.lower() == 'prune':
                    server.prune_boots_from_logs()
                    continue

                if i.lower() == 'compact_dump':
                    server.dump_all_compact()
                    continue

                if i.lower() == 'rm_last':
                    server.interactive_remove_recent()
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


if __name__ == '__main__':
    main()