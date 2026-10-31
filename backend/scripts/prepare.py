"""Validate CICDDoS2019 CSVs and report their schemas without copying the dataset."""
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[2]
files=sorted((ROOT/'data'/'raw').rglob('*.csv'))
if not files: raise SystemExit('No CSVs found in data/raw/')
for p in files:
    df=pd.read_csv(p,nrows=5,low_memory=False)
    label=next((c for c in df.columns if str(c).lower().strip() in {'label','class','target'}),None)
    print(f'{p.name}: columns={len(df.columns)} label={label}')
    if label: print(df[label].value_counts(dropna=False).to_dict())
