from scapy.all import sniff, ARP, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult
from multiprocessing import Process, Queue
from backend.keydb import KeyDBClient, DeviceRecord, ConnectionRecord
import ipaddress
import signal
import time

def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

class PacketCapture:
    def __init__(self, iface=None):
        self.iface = iface
        self.queue = Queue()
        self.process = None
        self.db = KeyDBClient()
        DATABASE.load()

    def capture_loop(self, queue, iface):
        def handle_packet(packet):
            ip = None
            mac = None
            metadata = {}

            if ARP in packet and packet[ARP].op in (1, 2):
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                metadata = {
                    "type": "ARP",
                    "src_ip": packet[ARP].psrc,
                    "src_mac": packet[ARP].hwsrc,
                    "dst_ip": packet[ARP].pdst,
                    "dst_mac": packet[ARP].hwdst
                }

            elif IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                mac = getattr(packet, "src", "00:00:00:00:00:00")

                metadata = {
                    "type": "IP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": packet[IP].proto
                }

                if is_local_ip(src_ip):
                    ip = src_ip
                    existing = self.db.get_device(ip)
                    if existing:
                        record = DeviceRecord(
                            ip=existing["ip"],
                            mac=existing["mac"],
                            metadata=existing.get("metadata", {})
                        )
                        record.update_metadata(metadata)
                    else:
                        record = DeviceRecord(ip=ip, mac=mac, metadata=metadata)

                    record.connections.append(ConnectionRecord(src_ip=src_ip, dst_ip=dst_ip))

                    self.db.store_device(record.to_dict())
                    queue.put(record.to_dict())

                if is_local_ip(src_ip):
                    self.db.store_connection(src_ip, dst_ip)
                elif is_local_ip(dst_ip):
                    self.db.store_connection(dst_ip, src_ip)

            if TCP in packet:
                try:
                    flags = packet[TCP].flags
                    if flags & 0x02:  # SYN or SYN+ACK
                        tcp_result: TCPResult = fingerprint_tcp(packet)
                        if tcp_result.match:
                            os_info = tcp_result.match.record.label
                            metadata.update({
                                "os": os_info.name,
                                "os_flavor": os_info.flavor,
                                "os_class": os_info.os_class
                            })
                            print(f"OS Match: src_ip={ip}, os={os_info.name}")
                except Exception as e:
                    print(f"Error fingerprinting TCP packet: {e}")

            if packet.haslayer(HTTPResponse):
                try:
                    payload = bytes(packet[Raw].load)
                    http_result: HTTPResult = fingerprint_http(payload)
                    if http_result and http_result.app_name:
                        metadata["http_app"] = http_result.app_name
                        metadata["http_version"] = http_result.version
                except Exception as e:
                    print(f"Error fingerprinting HTTP packet: {e}")

        sniff(iface=iface, prn=handle_packet, store=False)

    def start(self):
        self.process = Process(target=self.capture_loop, args=(self.queue, self.iface))
        self.process.start()

    def stop(self):
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join()