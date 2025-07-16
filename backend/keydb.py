import redis
import os
import time

class KeyDBClient:
    def __init__(self, host=None, port=6379, db=0):
        host = host or os.environ.get("KEYDB_HOST", "localhost")
        self.redis = redis.Redis(host=host, port=port, decode_responses=True)
        self.json = self.redis.json()

    def store_device(self, device):
        if not device.get("src_ip") or not device.get("src_mac"):
            return
        
        record = {
            "ip": device.get("src_ip"),
            "mac": device.get("src_mac"),
            "last_seen": time.time(),
            "metadata": device
        }

        self.json.set(f"device:{device.get('src_ip')}", record)

    def store_connection(self, src_ip, dst_ip):
        self.redis.set(f"link:{src_ip}->{dst_ip}", time.time())

    def get_all_devices(self):
        return [self.json.get(k) for k in self.redis.keys("device:*")]
    
    def get_device(self, ip):
        return self.json.get(f"device:{ip}")
    
    def clear_all(self):
        for k in self.redis.keys("device:*"):
            self.redis.delete(k)
        for k  in self.redis.keys("link:*"):
            self.redis.delete(k)