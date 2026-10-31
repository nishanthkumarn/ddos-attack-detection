"""Replay a CICFlowMeter-compatible CSV into the running detection API."""
from __future__ import annotations
import argparse, asyncio, os
import httpx, pandas as pd

LABELS={"Label","label","Class","class","Target","target"}
META={"Flow ID","Src IP","Dst IP","Src Port","Dst Port","Protocol","Timestamp","Label","label","Class","class","Target","target"}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("csv"); ap.add_argument("--url",default="http://127.0.0.1:8000/api/ingest"); ap.add_argument("--interval",type=float,default=.05); ap.add_argument("--limit",type=int,default=0); ap.add_argument("--api-key",default=os.getenv("API_KEY","")); args=ap.parse_args()
    headers={"x-api-key":args.api_key} if args.api_key else {}
    async def run():
        async with httpx.AsyncClient(timeout=10) as client:
            count=0
            for chunk in pd.read_csv(args.csv,chunksize=1000,low_memory=False):
                for _,r in chunk.iterrows():
                    if args.limit and count>=args.limit: return
                    src=str(r.get("Src IP","10.0.0.1")); dst=str(r.get("Dst IP","10.0.0.10"))
                    try: src_port=int(float(r.get("Src Port",0))); dst_port=int(float(r.get("Dst Port",r.get("Destination Port",0))))
                    except (TypeError,ValueError): src_port=0; dst_port=0
                    protocol=str(r.get("Protocol","TCP"))
                    features={str(k):float(v) for k,v in r.items() if k not in META and pd.notna(v)}
                    payload={"src_ip":src,"dst_ip":dst,"src_port":src_port,"dst_port":dst_port,"protocol":protocol,"features":features}
                    res=await client.post(args.url,json=payload,headers=headers)
                    res.raise_for_status(); count+=1
                    if count%100==0: print(f"replayed {count:,} flows")
                    await asyncio.sleep(args.interval)
            print(f"completed: {count:,} flows")
    asyncio.run(run())
if __name__=="__main__": main()
