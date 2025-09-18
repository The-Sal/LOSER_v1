"""Common Network Diagnostics functions for IC Audit. Can be used by both the agent and the server."""
import json
import subprocess


class NetworkDiagnostics:
    def __init__(self):
        pass

    @staticmethod
    def speedtest():
        """Requires Ookla Speedtest (official) to be installed."""
        try:
            output = subprocess.check_output(['speedtest', '-f', 'json'])
        except subprocess.CalledProcessError as e:
            print(f"Speedtest failed: {e}")
            return None
        except FileNotFoundError:
            print("Speedtest command not found. Please install Ookla Speedtest.")
            return None

        # Example output:
        # {"type": "result", "timestamp": "2025-09-18T07:25:27Z",
        #  "ping": {"jitter": 0.223, "latency": 1.638, "low": 1.349, "high": 1.709},
        #  "download": {"bandwidth": 108327415, "bytes": 791583936, "elapsed": 7306,
        #               "latency": {"iqm": 7.849, "low": 2.326, "high": 29.307, "jitter": 0.817}},
        #  "upload": {"bandwidth": 43644963, "bytes": 356491053, "elapsed": 8103,
        #             "latency": {"iqm": 2.203, "low": 1.412, "high": 214.640, "jitter": 16.216}}, "packetLoss": 0,
        #  "isp": "e& UAE",
        #  "interface": {"internalIp": "xxx.xxx.0.xxx", "name": "eth0", "macAddr": "xxxxxx", "isVpn": false,
        #                "externalIp": "xxx.xxx.xxx.xxx"},
        #  "server": {"id": 28422, "host": "speedtest2.etisalat.ae", "port": 8080, "name": "e& UAE",
        #             "location": "xxxxxx", "country": "xxxxx", "ip": "xxxxxx"},
        #  "result": {"id": "73a5e505-5350-4a0f-a938-56a37330e62b",
        #             "url": "https://www.speedtest.net/result/c/73a5e505-5350-4a0f-a938-56a37330e62b",
        #             "persisted": true}}

        return json.loads(output)

    @staticmethod
    def speedtest_installed():
        """Check if Ookla Speedtest is installed."""
        try:
            subprocess.check_output(['speedtest', '--version'])
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


if __name__ == '__main__':
    nd = NetworkDiagnostics()
    result = nd.speedtest()
    if result:
        print(json.dumps(result, indent=4))
