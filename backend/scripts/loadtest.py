"""Small dependency-free smoke/load test. Start the API first."""
import concurrent.futures, json, time, urllib.request
URL='http://127.0.0.1:8000/api/predict'; N=200; WORKERS=20
body=json.dumps({'features':{'pps':35000,'bps':9000000}}).encode(); headers={'Content-Type':'application/json'}
def one(_):
    req=urllib.request.Request(URL,data=body,headers=headers)
    t=time.perf_counter()
    with urllib.request.urlopen(req,timeout=5) as r: r.read(); return time.perf_counter()-t
with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
    ts=list(ex.map(one,range(N)))
print(f'requests={N} workers={WORKERS} avg_ms={sum(ts)/N*1000:.2f} p95_ms={sorted(ts)[int(.95*N)-1]*1000:.2f}')
