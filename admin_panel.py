from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from collections import Counter
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "your-secret-key"
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
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect('/keywords')  # Redirect to /keywords if user is already logged in

    if request.method == 'POST':
        user = request.form['username'] # test 
        pwd = request.form['password'] # test
        if user == USERNAME and pwd == PASSWORD:
            session['user'] = user
            return redirect('/index')
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

def login_required(route_func):
    from functools import wraps
    @wraps(route_func)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return route_func(*args, **kwargs)
    return wrapper

# --- Main Routes ---
# Landing Page
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/keywords')
@login_required
def keywords():
    entries = get_all_entries()
    return render_template("keywords.html", entries=entries)

# WAF Management Dashboard (Protected)
@app.route('/index')
def index():
    if 'user' not in session:
        flash('You must be logged in to access the WAF dashboard.', 'warning')
        return redirect(url_for('login'))
    else:
        return redirect('/keywords')
    
@app.route("/stats")
@login_required
def statistics():
    log_path = "waf_block_log.txt"
    date_counts = Counter()
    total_requests = 0
    last_30_days_requests = 0
    prev_30_days_requests = 0

    try:
        with open(log_path, "r") as f:
            logs = f.readlines()

        # Total requests (all-time count)
        total_requests = len(logs)

        # Current and previous 30 days calculation
        now = datetime.now()
        for line in logs:
            if line.strip():
                timestamp_str = line.split("]")[0][1:]
                try:
                    dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    if dt >= now - timedelta(days=30):
                        last_30_days_requests += 1
                    if dt >= now - timedelta(days=60) and dt < now - timedelta(days=30):
                        prev_30_days_requests += 1
                except:
                    continue

        # Percentage change for last 30 days
        if prev_30_days_requests > 0:
            percentage_change = ((last_30_days_requests - prev_30_days_requests) / prev_30_days_requests) * 100
        else:
            percentage_change = 0

    except FileNotFoundError:
        total_requests = 0
        last_30_days_requests = 0
        prev_30_days_requests = 0
        percentage_change = 0

    # Sorting the dates for chart data
    sorted_dates = sorted(date_counts.items())
    labels = [date for date, _ in sorted_dates]
    values = [count for _, count in sorted_dates]

    return render_template(
        "statistics.html",
        labels=labels,
        values=values,
        total_requests=total_requests,
        last_30_days_requests=last_30_days_requests,
        percentage_change=round(percentage_change, 2)  # Round for better display
    )


@app.route("/logs")
@login_required
def view_logs():
    log_path = "waf_block_log.txt"
    logs = []
    try:
        with open(log_path, "r") as f:
            logs = f.readlines()[-100:]  # Limit to last 100 entries
    except FileNotFoundError:
        logs = ["Log file not found."]
    return render_template("logs.html", logs=[line.strip() for line in logs])

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
