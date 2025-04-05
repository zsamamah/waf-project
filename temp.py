import sqlite3
import re

DB_PATH = "blocklist.db"
TEXT_FILE = "blocked_categories.txt"  # Your input file

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            keyword TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def import_from_txt():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        current_category = None
        for line in f:
            line = line.strip()
            if not line:
                continue
            if re.match(r"\[.+\]", line):  # Category line
                current_category = line[1:-1].lower()
            elif current_category:
                keyword = line.lower()
                cursor.execute(
                    "INSERT INTO blocked_keywords (category, keyword) VALUES (?, ?)",
                    (current_category, keyword)
                )

    conn.commit()
    conn.close()
    print("✅ Blocklist successfully imported to database.")

if __name__ == "__main__":
    init_db()
    import_from_txt()
