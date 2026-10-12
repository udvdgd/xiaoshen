# Python 实战 1：词频统计小工具（带作业）
```python
import sys
from collections import Counter

def count_words(path):
    with open(path, encoding="utf-8") as f:
        text=f.read().lower()
    words=[w for w in text.split() if w.isalpha()]
    return Counter(words)

if __name__=="__main__":
    if len(sys.argv)!=2:
        print("用法: python3 词频.py 文件.txt"); sys.exit(1)
    for word,n in count_words(sys.argv[1]).most_common(10):
        print(f"{word}: {n}")
```
教：sys.argv读参数、with open读文件、Counter统计、__main__入口。
作业：1.支持中文按字统计；2.加 -n 20 控制条数；3.结果写result.txt。
