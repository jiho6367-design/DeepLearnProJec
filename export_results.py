import sqlite3
import csv
from pathlib import Path

DB = Path(r"data/phishguard.db")
OUT = Path("data/results.csv")

# 테이블/컬럼명이 프로젝트마다 다를 수 있어요.
# 우선 가장 흔한 케이스: analysis_results 같은 테이블에
# base_prob/rule_score/fused/label/gt_label가 없을 수 있습니다.
# 그 경우에도 최소한 label/confidence/feedback/subject/body는 뽑아서 수작업 GT 붙인 뒤 eval에 넣을 수 있습니다.

conn = sqlite3.connect(DB)
cur = conn.cursor()

# 1) 테이블 목록 확인
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("tables:", tables)

# 2) analysis_results라는 테이블이 있다고 가정(없으면 출력된 테이블명으로 바꾸세요)
table = "analysis_results"
cols = [r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]
print("columns:", cols)

# 3) 가능한 컬럼만 골라서 export
wanted = ["base_prob","rule_score","fused","label","gt_label","rule_signals","confidence","feedback","subject","body","timestamp","gmail_id"]
use = [c for c in wanted if c in cols]

rows = cur.execute(f"SELECT {', '.join(use)} FROM {table} ORDER BY timestamp DESC").fetchall()

with OUT.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(use)
    w.writerows(rows)

print("wrote:", OUT.resolve())
conn.close()
