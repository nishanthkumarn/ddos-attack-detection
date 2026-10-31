"""Evaluate an exported labeled flow CSV against the trained artifact without mutating the database."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score
from app.flow_schema import normalize


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("csv"); ap.add_argument("--model",default="models/ddos_detector.joblib"); ap.add_argument("--limit",type=int,default=100000); args=ap.parse_args()
    art=joblib.load(args.model); df=pd.read_csv(args.csv,nrows=args.limit,low_memory=False)
    lc=next((c for c in df.columns if str(c).strip().lower() in {"label","class","target"}),None)
    if lc is None: raise SystemExit("labeled CSV required")
    y=df[lc].astype(str).str.strip().str.upper().ne("BENIGN").astype(int).to_numpy()
    X=[]
    for _,row in df.iterrows(): X.append([float(row.get(f,0) or 0) for f in art["feature_names"]])
    X=art["imputer"].transform(np.nan_to_num(np.asarray(X,dtype=float),nan=0,posinf=1e15,neginf=-1e15))
    p=art["model"].predict_proba(X)[:,1]; t=float(art["threshold"]); pred=(p>=t).astype(int)
    out={"rows":len(y),"threshold":t,"roc_auc":roc_auc_score(y,p),"average_precision":average_precision_score(y,p),"confusion_matrix":confusion_matrix(y,pred).tolist(),"classification_report":classification_report(y,pred,target_names=["BENIGN","DDoS"],output_dict=True,zero_division=0)}
    print(json.dumps(out,indent=2)); Path("models/replay_evaluation.json").write_text(json.dumps(out,indent=2))
if __name__=="__main__": main()
