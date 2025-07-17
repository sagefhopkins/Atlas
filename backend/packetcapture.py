from scapy.all import sniff, ARP, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult
from multiprocessing import Process, Queue
from backend.keydb import KeyDBClient
import signal
import time

class PacketCapture:
    def __init__(self, iface=None):
        self.iface = iface
        self.queue = Queue()
        self.process = None
        self.db = KeyDBClient()
        DATABASE.load()

    def capture_loop(self, queue, iface):
        def handle_packet(packet):
            data = {}

            if ARP in packet and packet[ARP].op in (1,2):
                data = {
                    "type": "ARP",
                    "src_ip": packet[ARP].psrc,
                    "src_mac": packet[ARP].hwsrc,
                    "dst_ip": packet[ARP].pdst,
                    "dst_mac": packet[ARP].hwdst
                }

                self.db.store_device(data)
            
            elif IP in packet:
                data = {
                    "type": "IP",
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": packet[IP].proto
                }
                self.db.store_device(data)
                self.db.store_connection(packet[IP].src, packet[IP].dst)

            if TCP in packet:
                    try:
                        flags = packet[TCP].flags
                        if flags & 0x02 != 0:
                            tcp_result: TCPResult = fingerprint_tcp(packet)
                            print(f"TCP Result: {tcp_result}")
                            if tcp_result and tcp_result.match and tcp_result.record:
                                record = tcp_result.record
                                data["os"] = record.label.name
                                data["os_flavor"] = record.label.flavor
                                data["os_class"] = record.label.os_class
                    except Exception as e:
                        print(f"Error fingerprinting TCP packet: {e}")
                    self.db.store_device(data)

            if packet.haslayer(HTTPResponse):
                try:
                    payload = bytes(packet[Raw].load)
                    http_result: HTTPResult = fingerprint_http(payload)
                    if http_result and http_result.app_name:
                        data["http_app"] = http_result.app_name
                        data["http_version"] = http_result.version
                except Exception as e:
                    print(f"Error fingerprinting HTTP packet: {e}")
                self.db.store_device(data)
                self.db.store_connection(packet[IP].src, packet[IP].dst)

            if data:
                queue.put(data)

        sniff(iface=iface, prn=handle_packet, store=False)

    def start(self):
        self.process = Process(target=self.capture_loop, args=(self.queue, self.iface))
        self.process.start()

    def stop(self):
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join()