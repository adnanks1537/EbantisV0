import argparse
import logging
import os
import signal
import sys
from datetime import datetime
from scapy.all import sniff, wrpcap
import platform

# Configuration
LOG_FILE = 'traffic_capture.log'
PCAP_DIR = 'pcap_files'
PID_FILE = 'traffic_capture.pid'

# Initialize logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure pcap directory exists
if not os.path.exists(PCAP_DIR):
    os.makedirs(PCAP_DIR)

class PacketCapture:
    def __init__(self):
        self.capturing = True
        self.pcap_file = os.path.join(PCAP_DIR, f"traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")

    def packet_callback(self, packet):
        wrpcap(self.pcap_file, packet, append=True)

    def start_capturing(self):
        sniff(prn=self.packet_callback, store=0)

    def stop_capturing(self, signum, frame):
        self.capturing = False
        logging.info("Packet capturing stopped")
        sys.exit(0)

    def run(self):
        signal.signal(signal.SIGTERM, self.stop_capturing)
        if platform.system() == "Windows":
            signal.signal(signal.SIGINT, self.stop_capturing)
            while self.capturing:
                self.start_capturing()
        else:
            self.daemonize()
            while self.capturing:
                self.start_capturing()

    def daemonize(self):
        if os.fork():
            sys.exit()
        os.setsid()
        if os.fork():
            sys.exit()
        sys.stdout.flush()
        sys.stderr.flush()
        with open('/dev/null', 'r') as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        with open('/dev/null', 'a') as devnull:
            os.dup2(devnull.fileno(), sys.stdout.fileno())
            os.dup2(devnull.fileno(), sys.stderr.fileno())
        write_pid(os.getpid())

def write_pid(pid):
    with open(PID_FILE, "w") as f:
        f.write(str(pid))

def read_pid():
    try:
        with open(PID_FILE, "r") as f:
            return int(f.read().strip())
    except Exception as e:
        logging.error(f"Error reading PID file: {e}")
        return None

def remove_pid():
    try:
        os.remove(PID_FILE)
    except Exception as e:
        logging.error(f"Error removing PID file: {e}")

def start():
    if platform.system() == "Windows":
        write_pid(os.getpid())
        PacketCapture().run()
    else:
        pid = os.fork()
        if pid == 0:
            PacketCapture().run()
        else:
            write_pid(pid)
            logging.info(f"Daemon started with PID {pid}")

def stop():
    pid = read_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            remove_pid()
            logging.info("Daemon stopped")
        except Exception as e:
            logging.error(f"Error stopping the daemon: {e}")
    else:
        logging.error("No PID found, is the daemon running?")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traffic Capture Daemon")
    parser.add_argument("action", choices=["start", "stop"], help="start or stop the daemon")
    args = parser.parse_args()

    if args.action == "start":
        start()
    elif args.action == "stop":
        stop()
