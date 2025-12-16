import sqlite3
from pathlib import Path
path = Path(r'C:\Users\USER\PhishGuard_Project\data\phishguard.db')
conn = sqlite3.connect(path)
cur = conn.cursor()
cols = cur.execute('PRAGMA table_info(email_analysis)').fetchall()
print('email_analysis columns:', cols)
rows = cur.execute('SELECT label, confidence, feedback FROM email_analysis LIMIT 50').fetchall()
for r in rows:
    print(r)
