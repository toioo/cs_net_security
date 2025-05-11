from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# 规则
attack_rules = {
    "nmap_stealth_scan": {
        "flags": "S",
        "port_access_rate": 20  # 设置一个较低阈值便于测试
    }
}

# 状态记录
ip_access_log = defaultdict(lambda: {"ports": set(), "last_time": time.time()})

def detect_threat(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    src_ip = packet[IP].src
    dport = packet[TCP].dport
    flags = packet[TCP].flags

    if flags == attack_rules["nmap_stealth_scan"]["flags"]:
        now = time.time()
        ip_access_log[src_ip]["ports"].add(dport)
        duration = now - ip_access_log[src_ip]["last_time"]

        if duration > 1:
            rate = len(ip_access_log[src_ip]["ports"]) / duration
            if rate > attack_rules["nmap_stealth_scan"]["port_access_rate"]:
                print(f"[!!!] Port scan detected from {src_ip} ({rate:.2f} ports/sec)")
                ip_access_log[src_ip] = {"ports": set(), "last_time": now}
                return "nmap_stealth_scan"
            else:
                ip_access_log[src_ip] = {"ports": set(), "last_time": now}
    return None

# 捕包处理函数
def packet_handler(packet):
    threat_type = detect_threat(packet)
    if threat_type:
        print(f"[ALERT] Detected {threat_type} from {packet[IP].src}")
    # print(packet.summary())  # 可选调试

if __name__ == "__main__":
    print("[*] Starting packet sniffing on interface eth0...")
    sniff(iface="eth0", prn=packet_handler, store=0, filter="tcp", promisc=True)
