import time
from collections import defaultdict, deque

# sliding window in seconds
DEFAULT_WINDOW = 60  # 60 seconds window, tuneable

class FlowCounters:
    def __init__(self, window_seconds=DEFAULT_WINDOW):
        self.window = window_seconds
        # per src -> deque of timestamps
        self.src_times = defaultdict(deque)
        # per (src,dst) -> deque of timestamps
        self.src_dst_times = defaultdict(deque)
        # per dst -> deque of timestamps
        self.dst_times = defaultdict(deque)

    def tick(self, src_ip, dst_ip):
        now = time.time()
        # push
        self.src_times[src_ip].append(now)
        self.src_dst_times[(src_ip, dst_ip)].append(now)
        self.dst_times[dst_ip].append(now)
        # cleanup old entries
        cutoff = now - self.window
        # cleanup only the modified keys for speed
        dq = self.src_times[src_ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq2 = self.src_dst_times[(src_ip, dst_ip)]
        while dq2 and dq2[0] < cutoff:
            dq2.popleft()
        dq3 = self.dst_times[dst_ip]
        while dq3 and dq3[0] < cutoff:
            dq3.popleft()

    def get_counts(self, src_ip, dst_ip):
        # counts within window
        src_count = len(self.src_times.get(src_ip, []))
        src_dst_count = len(self.src_dst_times.get((src_ip, dst_ip), []))
        dst_count = len(self.dst_times.get(dst_ip, []))
        return {
            "ct_src_ltm": src_count,
            "ct_srv_src": src_dst_count,
            "ct_dst_ltm": dst_count
        }

# create a module-level default instance (import and use)
_default_fc = FlowCounters()

def tick_packet(src_ip, dst_ip):
    try:
        _default_fc.tick(src_ip, dst_ip)
    except Exception:
        pass

def get_packet_counts(src_ip, dst_ip):
    try:
        return _default_fc.get_counts(src_ip, dst_ip)
    except Exception:
        return {"ct_src_ltm": 0, "ct_srv_src": 0, "ct_dst_ltm": 0}
