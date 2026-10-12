# Python 实战 1：词频统计小工具（带作业）
```python
import sys
from collections import Counter
def count_words(path):
    with open(path, encoding="utf-8") as f: t=f.read().lower()
    return Counter(w for w in t.split() if w.isalpha())
if __name__=="__main__":
    if len(sys.argv)!=2: print("用法: python3 词频.py 文件.txt"); raise SystemExit(1)
    for w,n in count_words(sys.argv[1]).most_common(10): print(w,n)
```
作业：1.中文按字统计；2.-n 20控制条数；3.结果写result.txt。
