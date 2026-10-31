"""Run a CICFlowMeter-compatible extractor, then optionally replay its CSV.

The supported Python CICFlowMeter CLI exposes -f/--file and -i/--interface inputs.
This wrapper deliberately does not invent a packet-to-feature implementation: the
same flow generator should be used for training-parity demonstrations.
"""
from __future__ import annotations
import argparse
import os
import subprocess
import sys


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--pcap"); ap.add_argument("--interface"); ap.add_argument("--output",required=True); ap.add_argument("--replay",action="store_true"); ap.add_argument("--api",default="http://127.0.0.1:8000/api/ingest"); ap.add_argument("--api-key",default=os.getenv("API_KEY","")); args=ap.parse_args()
    if bool(args.pcap)==bool(args.interface): raise SystemExit("choose exactly one of --pcap or --interface")
    cmd=["cicflowmeter"]
    if args.pcap: cmd += ["-f",args.pcap]
    if args.interface: cmd += ["-i",args.interface]
    cmd += ["-c",args.output]
    print("Executing:"," ".join(cmd))
    subprocess.run(cmd,check=True)
    if args.replay:
        from replay_csv import main as replay_main
        sys.argv=[sys.argv[0],args.output,"--url",args.api]
        if args.api_key: sys.argv += ["--api-key",args.api_key]
        replay_main()

if __name__=="__main__": main()
