import json
import time
import socket
from utils3 import redundancy, runAsThread


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

    def __init__(self, project_name, project_market, project_description, project_privileges=None, **kwargs):
        """Initialize the audit notifier client.
        
        Args:
            project_name: Name identifier for the project
            project_market: Market context the project operates in
            project_description: Description of the project's purpose
            project_privileges: Single privilege or list of ProjectPrivileges
            **kwargs: Additional metadata to include with all events
        """
        self._project_name = project_name
        self._project_market = project_market
        self._project_description = project_description
        self._project_privileges = project_privileges if isinstance(project_privileges, list) else [project_privileges]
        self._kwargs = kwargs
        self._server_address = ('localhost', 9324)
        self._boot_time = time.time()
        self.send(ProjectEvents.BOOT, "Project was booted.")

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


if __name__ == '__main__':
    svr = AuditNotifier(
        project_name='Test Project',
        project_market='Test Market',
        project_description='This is a test project for auditing purposes.'
    )

    print("Interactive Audit Notifier Test")
    print("Available event types:")
    for attr in dir(ProjectEvents):
        if not attr.startswith('_'):
            print(f"  - {attr}: {getattr(ProjectEvents, attr)}")

    try:
        while True:
            print("\nOptions:")
            print("1. Send custom event")
            print("2. Send trade opened event")
            print("3. Send trade closed event")
            print("4. Send error event")
            print("5. Exit")

            choice = input("Select option (1-5): ").strip()

            if choice == '1':
                event_type = input("Enter event type: ").strip()
                description = input("Enter event description: ").strip()
                svr.send(event_type, description)
                print("Custom event sent!")

            elif choice == '2':
                symbol = input("Enter trade symbol: ").strip()
                price = input("Enter trade price: ").strip()
                svr.send(ProjectEvents.TRADE_OPENED, f"Trade opened for {symbol}",
                         symbol=symbol, price=price)
                print("Trade opened event sent!")

            elif choice == '3':
                symbol = input("Enter trade symbol: ").strip()
                profit = input("Enter profit/loss: ").strip()
                svr.send(ProjectEvents.TRADE_CLOSED, f"Trade closed for {symbol}",
                         symbol=symbol, profit=profit)
                print("Trade closed event sent!")

            elif choice == '4':
                error_msg = input("Enter error message: ").strip()
                svr.send(ProjectEvents.ERROR, error_msg)
                print("Error event sent!")

            elif choice == '5':
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please select 1-5.")

    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
