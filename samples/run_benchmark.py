#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量跑分: 对 test_corpus 跑真实流水线, 统计四类指标。"""
import os,sys,json,time
from pathlib import Path
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0,ROOT)
from py.core.main import detect_and_decrypt
from py.core.utils import looks_like_script
BASE=Path(os.path.dirname(os.path.abspath(__file__)))/"test_corpus"
CATS=["recoverable","noise","hard_enc","obfuscated"]
def is_script(o):
    try: return looks_like_script(o)
    except Exception: return False
def main():
    report={}; t0=time.time()
    for cat in CATS:
        files=sorted((BASE/cat).glob("*")); total=len(files); success=0; bad=0; hist={}
        for f in files:
            try:
                r=detect_and_decrypt(f); out=r.get("output",b"")
            except Exception: out=f.read_bytes()
            ok=is_script(out)
            for s in r.get("stages",[]):
                k=s.split(":")[0]; hist[k]=hist.get(k,0)+1
            if cat=="recoverable":
                if ok: success+=1
            elif ok: bad+=1
        if cat=="recoverable": report[cat]={"total":total,"recovered":success,"recall_pct":round(100*success/total,1)}
        else: report[cat]={"total":total,"false_became_script":bad,"false_pct":round(100*bad/total,1)}
        report[cat]["top_stages"]=dict(sorted(hist.items(),key=lambda x:-x[1])[:6])
    report["_elapsed_sec"]=round(time.time()-t0,1)
    (BASE/"benchmark_result.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps(report,ensure_ascii=False,indent=2))
if __name__=="__main__": main()
