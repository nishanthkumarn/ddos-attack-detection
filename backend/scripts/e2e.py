import sys
import urllib.request
import json
base='http://127.0.0.1:8000'
try:
    with urllib.request.urlopen(base+'/health',timeout=3) as r: assert r.status==200
    req=urllib.request.Request(base+'/api/predict',data=json.dumps({'features':{'pps':50000,'bps':12000000}}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=3) as r: assert json.load(r)['label'] in ('BENIGN','DDoS')
    print('E2E PASS')
except Exception as e:
    print('E2E FAIL:',e); sys.exit(1)
