import sqlite3

conn = sqlite3.connect("blocklist.db")
cursor = conn.cursor()

# Create table for categories and keywords
cursor.execute("""
CREATE TABLE IF NOT EXISTS blocked_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    keyword TEXT NOT NULL
)
""")

# Example insert
sample_data = [
    ("social media", "facebook"),
    ("social media", "instagram"),
    ("adult", "porn"),
    ("adult", "xvideos"),
    ("gambling", "bet365"),
    ("gambling", "casino")
]

cursor.executemany("INSERT INTO blocked_keywords (category, keyword) VALUES (?, ?)", sample_data)

conn.commit()
conn.close()
