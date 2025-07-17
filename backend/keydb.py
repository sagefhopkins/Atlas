import redis
import os
import time

class KeyDBClient:
    def __init__(self, host=None, port=6379, db=0):
        host = host or os.environ.get("KEYDB_HOST", "localhost")
        self.redis = redis.Redis(host=host, port=port, decode_responses=True)
        self.json = self.redis.json()

    def _safe_json_set(self, key, path, obj):
        try:
            self.json.set(key, path, obj)
        except redis.exceptions.ResponseError as e:
            if "WRONGTYPE" in str(e):
                self.redis.delete(key)
                self.json.set(key, path, obj)
            else:
                raise

    def store_device(self, device):
        if not device.get("src_ip") or not device.get("src_mac"):
            return
        key = f"device:{device['src_ip']}"
        existing = self.get_device(device["src_ip"])
        metadata = device.get("metadata", {}) if existing else {}

        for k, v in device.items():
            if k not in ("src_ip", "src_mac"):
                metadata[k] = v

        record = {
            "src_ip": device["src_ip"],
            "src_mac": device["src_mac"],
            "last_seen": time.time(),
            "metadata": metadata,
        }
        self._safe_json_set(key, ".", record)

    def store_connection(self, src_ip, dst_ip):
        self._safe_json_set(f"link:{src_ip}->{dst_ip}", ".", {"timestamp": time.time()})

    def get_all_devices(self):
        return [self.json.get(k) for k in self.redis.keys("device:*")]

    def get_device(self, ip):
        return self.json.get(f"device:{ip}")
    
    def clear_all(self):
        for k in self.redis.keys("device:*"):
            self.redis.delete(k)
        for k  in self.redis.keys("link:*"):
            self.redis.delete(k)
