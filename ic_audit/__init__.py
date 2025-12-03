import os
import sys
import json
import time
import socket
import subprocess
import threading
from utils3 import redundancy, runAsThread
from ic_audit.machine import main as audit_machine_main, init_machine
from ic_audit.ui import MachineConfigUI


class ProjectPrivileges:
    """Defines privilege levels for project operations.
    
    These constants define what actions a project is authorized to perform
    within the audit system. Used by AuditNotifier to track project capabilities.
    """
    EXECUTE_TRADE = 'execute_trade'
    POST_MORTEM_ANALYSIS = 'post_mortem_analysis'
    LIVE_MONITORING = 'live_monitoring'
    UTILITIES = 'utilities'


class ProjectEvents:
    """Standard event types for audit logging.
    
    These constants define the types of events that can be logged to the audit server.
    Each event type represents a significant action or state change in the project.
    """
    BOOT = 'boot'
    ERROR = 'error'
    TRADE_OPENED = 'trade_opened'
    TRADE_CLOSED = 'trade_closed'
    UNCLASSIFIED_EVENT = 'unclassified_event'


class ProjectEventObj:
    """Represents a single audit event with metadata.
    
    Encapsulates all information about an audit event including type, description,
    timestamp, and any additional context data.
    """

    def __init__(self, event_type: ProjectEvents, event_description: str, **kwargs):
        """Initialize a project event object.
        
        Args:
            event_type: Type of event from ProjectEvents enum
            event_description: Human-readable description of the event
            **kwargs: Additional context data to include with the event
        """
        self.event_type = event_type
        self.event_description = event_description
        self.timestamp = time.time()
        self.additional_info = kwargs

    def to_dict(self):
        """Convert the event object to a dictionary for serialization.
        
        Returns:
            dict: Dictionary representation containing event_type, event_description,
                  timestamp, and any additional_info fields
        """
        base = {
            'event_type': self.event_type,
            'event_description': self.event_description,
            'timestamp': self.timestamp,
            **self.additional_info
        }

        return base


class AuditNotifier:
    """Client for sending audit events to the audit server.
    
    Handles communication with the audit server running on localhost:9324.
    Automatically sends a boot event upon initialization and provides methods
    to send various types of audit events throughout the project lifecycle.
    """

    def __init__(self, project_name, project_market, project_description, project_privileges=None,
                 pid=os.getpid(), **kwargs):
        """Initialize the audit notifier client.
        
        Args:
            project_name: Name identifier for the project
            project_market: Market context the project operates in
            project_description: Description of the project's purpose
            project_privileges: Single privilege or list of ProjectPrivileges
            pid: Process ID of the project instance (default: current process)
            **kwargs: Additional metadata to include with all events
        """
        self._project_name = project_name
        self._project_market = project_market
        self._project_description = project_description
        self._project_privileges = project_privileges if isinstance(project_privileges, list) else [project_privileges]
        self._kwargs = kwargs
        self._server_address = ('localhost', 9324)
        self._boot_time = time.time()
        self.send(ProjectEvents.BOOT, "Project was booted.", booted_with_pid=pid)

    @runAsThread
    @redundancy(lambda *args, **kwargs: None)
    def _send(self, msg):
        """Internal method to send messages to the audit server.
        
        Runs in a separate thread with redundancy protection. Establishes
        a TCP connection to the audit server and sends the JSON-encoded message.
        
        Args:
            msg: Dictionary message to send to the audit server
        """
        msg = json.dumps(msg)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(self._server_address)
            sock.sendall(msg.encode())
            response = sock.recv(1024)
            _ = response

    def send(self, event_type, event_description, **kwargs):
        """Send an audit event to the server.
        
        Creates a ProjectEventObj and sends it to the audit server with
        project metadata included.
        
        Args:
            event_type: Type of event from ProjectEvents
            event_description: Description of what happened
            **kwargs: Additional event-specific data
        """
        obj = ProjectEventObj(event_type, event_description, **kwargs)
        msg = obj.to_dict()
        msg.update({
            'project_name': self._project_name,
            'project_market': self._project_market,
            'project_description': self._project_description,
            'project_privileges': self._project_privileges if self._project_privileges else [],
            **self._kwargs
        })
        self._send(msg)

    def notify(self, event_type, event_description, **kwargs):
        """Alias for send() method.
        
        Provides an alternative interface for sending audit notifications.
        
        Args:
            event_type: Type of event from ProjectEvents
            event_description: Description of what happened
            **kwargs: Additional event-specific data
        """
        self.send(event_type, event_description, **kwargs)


def fast_audit(project_name, project_market, project_description):
    """Convenience function for quick audit notification.
    
    Creates an AuditNotifier instance and sends a boot event to the audit server.
    Intended for command-line usage or simple one-off audit notifications.
    
    Args:
        project_name: Name identifier for the project
        project_market: Market context the project operates in  
        project_description: Description of the project's purpose
        
    Returns:
        None: Function executes for side effects only
    """
    _ = AuditNotifier(project_name, project_market, project_description)


def trigger_audit_dumping():
    """Trigger a dump of the current audit trails.

    Sends a special command to the audit server to dump all collected audit trails.
    Intended for use in debugging or manual inspection of audit data.

    Returns:
        None: Function executes for side effects only
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 9324))
        sock.sendall(b'dump_audit_trails')
        response = sock.recv(1024)
        print(f"Server response: {response.decode()}")


def trigger_audit_dumping_all():
    """Trigger a dump of all audit trails, not just today's.

    Sends a special command to the audit server to dump all collected audit trails,
    regardless of date. Useful for comprehensive audits or backups.

    Returns:
        None: Function executes for side effects only
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 9324))
        sock.sendall(b'dump_audit_trails_all')
        response = sock.recv(1024)
        print(f"Server response: {response.decode()}")

def trigger_audit_compact(filters: list[str] = None):
    """
    Trigger compaction of audit trails based on specified filters.
    :param filters: If specified, only compact trails matching these filters.
                    If None, compacts all trails.
    :return:
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 9324))
        command = 'dump_compact'
        if filters:
            command += '_with_filter:' + ','.join(filters)
        sock.sendall(command.encode())
        response = sock.recv(1024)
        print(f"Server response: {response.decode()}")


def available_audit_projects():
    """Retrieve a list of projects with audit trails.

    Connects to the audit server and requests a list of all projects
    that have recorded audit events.

    Returns:
        list: List of project names with audit trails
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 9324))
        sock.sendall(b'available_projects')
        response = sock.recv(4096)
        projects = json.loads(response.decode())
        return projects


def start_audit_machine(use_screen=False):
    """Start the audit server machine in a non-blocking manner.

    Launches the audit server in a background thread and displays an interactive
    UI for managing machine configuration. The server continues running even after
    the UI is closed.

    Args:
        use_screen (bool): If True, start in a screen session using 'screen -dmS ic.audit'.
                          If False, start in a background thread with interactive UI.

    Returns:
        None: Function executes for side effects only
    """
    if use_screen:
        # Get the path to the current Python executable and this module
        python_exe = sys.executable
        module_path = os.path.abspath(__file__)
        # Start as a screen session: screen -dmS ic.audit python -m ic_audit
        subprocess.Popen([
            'screen', '-dmS', 'ic.audit',
            python_exe, '-m', 'ic_audit'
        ])
    else:
        # Initialize machine in main thread (handles machine ID prompt if needed)
        machine = init_machine()

        # Start the server socket loop in a background thread (non-blocking)
        server_thread = threading.Thread(target=machine.spin_socket_server, daemon=False)
        server_thread.start()

        # Give the server a moment to start listening
        time.sleep(0.5)

        # Launch the interactive UI in the main thread
        ui = MachineConfigUI()
        ui.run()


if __name__ == '__main__':
    use_screen = '--screen' in sys.argv
    start_audit_machine(use_screen=use_screen)
