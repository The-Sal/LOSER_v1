import json
import time
import socket
from utils3 import redundancy, runAsThread

class AuditNotifier:
    def __init__(self, project_name, project_market, **kwargs):
        self.project_name = project_name
        self.project_market = project_market
        self.additional_info = kwargs
        self.server_address = ('localhost', 9324)
        self.boot_time = time.time()

        self._send({
            'type': 'boot',
            'project_name': self.project_name,
            'project_market': self.project_market,
            'boot_time': self.boot_time,
            'timestamp': time.time(),
            **self.additional_info
        })

    @runAsThread
    @redundancy(lambda *args, **kwargs: None)
    def _send(self, msg):
        msg = json.dumps(msg)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(self.server_address)
            sock.sendall(msg.encode())
            response = sock.recv(1024)

    def notify(self, event_type, **kwargs):
        msg = {
            'type': event_type,
            'project_name': self.project_name,
            'project_market': self.project_market,
            'timestamp': time.time(),
            **self.additional_info,
            **kwargs
        }
        self._send(msg)