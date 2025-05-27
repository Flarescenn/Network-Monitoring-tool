import socket
import time
import threading
import ipaddress
from collections import OrderedDict

class ReverseDNSResolver:
    def __init__(self, max_size=1024, cache_ttl=3600, neg_cache_ttl=600):
        self.cache = OrderedDict()  # IP -> (hostname_or_None, timestamp, is_negative_entry)
        self.max_size = max_size
        self.cache_ttl = cache_ttl
        self.neg_cache_ttl = neg_cache_ttl
        self.lock = threading.Lock()

    def _is_resolvable_ip(self, ip_address_str: str) -> bool:
        # To check if the IP address is a global unicast address
        try:
            ip_obj = ipaddress.ip_address(ip_address_str)
            return ip_obj.is_global and not ip_obj.is_multicast and \
                   not ip_obj.is_loopback and not ip_obj.is_link_local and \
                   not ip_obj.is_reserved
        except ValueError:
            return False
    
    def get_hostname(self, ip_address: str) -> str | None:
        if not self._is_resolvable_ip(ip_address): # if it is not a valid resolvable IP
            return None 

        with self.lock:
            if ip_address in self.cache:
                hostname, timestamp, is_neg = self.cache[ip_address]
                ttl_to_use = self.neg_cache_ttl if is_neg else self.cache_ttl  #
                if (time.monotonic() - timestamp) < ttl_to_use: # 
                    self.cache.move_to_end(ip_address) # 
                    return hostname # Can be None if it was a negative cache hit
                del self.cache[ip_address] # Expired

        try:
           
            hostname_tuple = socket.gethostbyaddr(ip_address)
            hostname = hostname_tuple[0] if hostname_tuple else None
            is_neg_entry = False if hostname else True
        except (socket.herror, socket.gaierror, socket.timeout):
            hostname = None
            is_neg_entry = True
        except Exception: # Catch any other unexpected socket error
            hostname = None
            is_neg_entry = True # Treat unexpected errors as negative cacheable events

        with self.lock:
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False) # LRU eviction
            self.cache[ip_address] = (hostname, time.monotonic(), is_neg_entry)
        return hostname

if __name__ == "__main__":
    resolver = ReverseDNSResolver()
    test_ip = "199.59.149.230"  # twitter
    print(f"Hostname for {test_ip}: {resolver.get_hostname(test_ip)}")
    #test_ip_invalid = "999.999.999.999"
    #print(f"Hostname for invalid IP {test_ip_invalid}: {resolver.get_hostname(test_ip_invalid)}")