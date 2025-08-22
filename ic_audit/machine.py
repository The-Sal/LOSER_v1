"""Often times there are multiple machines that need to be audited as alive or dead. This module is the server-side
code that will allow the audit system to discover and read the status of machines in a network."""
import os
import time
import json
import pickle
import socket
import traceback

from utils3 import runAsThread
from utils3.system import allProcesses, Process

_MACHINE_CACHE = os.path.join(os.path.dirname(__file__), 'machine_cache.pkl')
_AUDIT_PORT = 9631


class AuditableMachine:
    """Represents a machine that can be audited for its status. The way it works essentially is that
    each machine will have a list of file paths of programs that are 'supposed' to be running on it. When
    audited it will use ps aux to check if those programs are running and return a status of the machine and it's
    subsystems. It will also return information like how long it's been alive and the number of restarts
    in the last 24 hours. The configuration of what files are expected to be running is loaded from a JSON file named
    'machine_config.json' that should be located in the cwd of this class. Example:
    {
      "Dart Server": {
        "name": "Dart Server",
        "description": "The Server for the DartAI",
        "filepath": "/Users/Pi/home/CrossLanguage/Dart/Builds/Dart2.1/server.py"
      }
    }
    """

    def __init__(self, machine_id: str):
        """Initialize an AuditableMachine instance.

        Args:
            machine_id (str): Unique identifier for the machine.
        """
        self.data = self.load_machine_cache()

        if 'machine_id' in self.data:
            self.machine_id = self.data['machine_id']
        else:
            if machine_id is None:
                raise ValueError("Machine ID must be provided for new machines.")
            self.machine_id = machine_id
            self.data['machine_id'] = machine_id
            self.write_machine_cache()

        self.socket = socket.socket(socket.AF_INET)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', _AUDIT_PORT))
        self.machine_config = self.load_machine_config()
        print(f"Machine {self.machine_id} initialized with config:")
        print(json.dumps(self.machine_config, indent=4))
        self._boot_event()

    @staticmethod
    def load_machine_config():
        """Load the machine configuration from a JSON file."""
        config_path = os.path.join(os.getcwd(), 'machine_config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        else:
            raise FileNotFoundError(f"Machine configuration file not found: {config_path}")

    def _boot_event(self):
        try:
            self.data['boot_times'].append(time.time())
        except KeyError:
            self.data['boot_times'] = [time.time()]
        self.write_machine_cache()

    def spin_socket_server(self):
        """Start the socket server to listen for audit requests."""
        self._update_last_alive_msg()  # Start the thread to update last alive messages
        while True:
            self.socket.listen()
            conn, addr = self.socket.accept()
            self._process_connection(conn, addr)

    @runAsThread
    def _process_connection(self, conn, addr):
        """Process incoming connections and handle audit requests."""
        _ = addr
        try:
            data = conn.recv(1024)
            if not data:
                return
            request = data.decode('utf-8').strip()
            if request == 'audit':
                report = self.generate_audit_report()
                response = json.dumps(report).encode('utf-8')
                size_of_response = len(response)
                conn.sendall(size_of_response.to_bytes(4, 'big') + response)
            else:
                conn.sendall(b'0000')  # Unknown request, send empty response
        except Exception as e:
            print(f"Error processing connection: {e}")
        finally:
            conn.close()

    @runAsThread
    def _update_last_alive_msg(self):
        while True:
            time.sleep(1)
            try:
                self.data['last_alive'].append(time.time())
            except KeyError:
                self.data['last_alive'] = [time.time()]

            if len(self.data['last_alive']) > 172_800:  # that is about 2 days of 1s intervals
                self.data['last_alive'] = self.data['last_alive'].pop(0)  # remove the oldest entry

            self.write_machine_cache()

    @staticmethod
    def load_machine_cache():
        """Load the machine cache from disk."""
        if os.path.exists(_MACHINE_CACHE):
            with open(_MACHINE_CACHE, 'rb') as f:
                return pickle.load(f)
        return {}

    def write_machine_cache(self):
        """Write the current machine data to the cache file."""
        with open(_MACHINE_CACHE, 'wb') as f:
            pickle.dump(self.data, f)

    def get_active_processes(self):
        """Get a list of active processes on the machine."""
        procs: list[Process] = allProcesses()
        conf = self.machine_config
        # We want to create a reverse map of filepath to config entry
        # that way we can quickly check is the file path exists in the process
        # and key to the config entry
        config_keys = list(conf.keys())
        filepath_to_key = {conf[key]['filepath']: key for key in config_keys}
        active_processes = {}
        for proc in procs:
            for filepath, key in filepath_to_key.items():
                if filepath in proc.cmd:
                    active_processes[key] = {
                        'pid': proc.pid,
                        'name': conf[key]['name'],
                        'description': conf[key]['description'],
                        'status': 'running'
                    }

        # Now we want to check for any config entries that are not in active_processes
        for key in config_keys:
            if key not in active_processes:
                active_processes[key] = {
                    'pid': None,
                    'name': conf[key]['name'],
                    'description': conf[key]['description'],
                    'status': 'not running'
                }

        return active_processes

    def generate_audit_report(self):
        """Generate a report of the machine's status."""
        this_session_boot = self.data['boot_times'][-1]
        last_24h_boots = len(self.data['boot_times'])
        current_up_time = time.time() - this_session_boot
        report = {
            'machine_id': self.machine_id,
            'current_time': time.time(),
            'this_session_boot_time': this_session_boot,
            'last_24h_boots': last_24h_boots,
            'current_up_time_seconds': current_up_time,
            'active_processes': self.get_active_processes(),
        }

        return report


def main(machine_id: str | None = None):
    try:
        machine = AuditableMachine(machine_id)
        machine.spin_socket_server()
    except ValueError as e:
        print("An error occurred while initializing the machine")
        traceback.print_exc()
        print("Machine ID must be provided for new machines.")
        i = input("Enter a unique machine ID (e.g., hostname or UUID): ").strip()
        main(i)

if __name__ == '__main__':
    main()