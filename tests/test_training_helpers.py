import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'backend'))
from scripts.train import label_col

def test_label_col(): assert label_col(['A','Label'])=='Label'
