from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "your-secret-key"  # 🔐 Replace with a strong secret key
DB_PATH = "blocklist.db"

USERNAME = "admin"
PASSWORD = "123321"

# --- DB Setup ---
def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE blocked_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            keyword TEXT NOT NULL
        )""")
        conn.commit()
        conn.close()

def get_all_entries():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, category, keyword FROM blocked_keywords ORDER BY category")
    rows = cursor.fetchall()
    conn.close()
    return rows

def add_entry(category, keyword):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO blocked_keywords (category, keyword) VALUES (?, ?)", (category, keyword))
    conn.commit()
    conn.close()

def delete_entry(entry_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_keywords WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()

# --- Auth ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == USERNAME and request.form["password"] == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def login_required(route_func):
    from functools import wraps
    @wraps(route_func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return route_func(*args, **kwargs)
    return wrapper

# --- Main Routes ---
@app.route("/")
@login_required
def index():
    entries = get_all_entries()
    return render_template("index.html", entries=entries)

@app.route("/add", methods=["POST"])
@login_required
def add():
    category = request.form["category"]
    keyword = request.form["keyword"]
    if category and keyword:
        add_entry(category.strip(), keyword.strip())
    return redirect(url_for("index"))

@app.route("/delete/<int:entry_id>")
@login_required
def delete(entry_id):
    delete_entry(entry_id)
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
