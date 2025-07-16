from scapy.all import sniff, ARP, IP, TCP, UDP
from multiprocessing import Process, Queue
from keydb import KeyDBClient
import signal
import time

class PacketCapture:
    def __init__(self, iface=None):
        self.iface = iface
        self.queue = Queue()
        self.process = None
        self.db = KeyDBClient()

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