"""Replay a PCAP through an approximate packet-to-flow adapter.

Use CICFlowMeter-generated CSV replay when model feature parity matters.
"""
import argparse
from app.pcap import replay_pcap
from app.model import detector

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('pcap'); ap.add_argument('--interval',type=float,default=.05); ap.add_argument('--max-packets',type=int,default=0); args=ap.parse_args()
    def cb(flow):
        label,p,conf,severity,signals,mode=detector.predict(flow['features'])
        print(flow['src_ip'],flow['dst_ip'],label,f'p={p:.3f}',severity,mode)
    replay_pcap(args.pcap,cb,args.interval,args.max_packets)
if __name__=='__main__': main()
