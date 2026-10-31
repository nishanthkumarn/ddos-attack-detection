"""Best-effort PCAP flow aggregation for lab replay.

For model parity, generate CICFlowMeter CSV first and replay that CSV. PCAP mode is
intentionally marked `pcap_approximation`: it demonstrates packet-to-flow plumbing,
not exact CICFlowMeter feature parity.
"""
from dataclasses import dataclass
import time

@dataclass
class Flow:
    src: str; dst: str; sport: int; dport: int; proto: str; first: float; last: float
    packets: int = 0; bytes: int = 0


def replay_pcap(path: str, callback, interval: float = 0.05, max_packets: int = 0):
    try:
        from scapy.all import IP, TCP, UDP, rdpcap
    except ImportError as exc:
        raise RuntimeError("PCAP replay requires scapy; install the optional pcap dependencies") from exc
    packets = rdpcap(path)
    flows = {}
    count = 0
    for pkt in packets:
        if IP not in pkt: continue
        ip = pkt[IP]; proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else str(ip.proto)
        sport = int(pkt.sport) if hasattr(pkt, "sport") else 0; dport = int(pkt.dport) if hasattr(pkt, "dport") else 0
        key=(ip.src,ip.dst,sport,dport,proto); ts=float(getattr(pkt,"time",time.time()))
        f=flows.get(key)
        if not f: f=flows[key]=Flow(*key,ts,ts)
        f.last=ts; f.packets+=1; f.bytes+=len(pkt); count+=1
        duration=max((f.last-f.first)*1000, 1.0)
        features={"Flow Duration":duration,"Total Fwd Packets":float(f.packets),"Total Backward Packets":0.0,
                  "Destination Port":float(dport),"Flow Packets/s":f.packets/max(duration/1000,1e-3),
                  "Flow Bytes/s":f.bytes/max(duration/1000,1e-3)}
        callback({"src_ip":ip.src,"dst_ip":ip.dst,"src_port":sport,"dst_port":dport,"protocol":proto,"features":features,"mode":"pcap_approximation"})
        if interval: time.sleep(interval)
        if max_packets and count >= max_packets: break
