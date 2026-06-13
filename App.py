"""
CTF Challenge: "Admin Panel" - Intermediate Web Exploitation
Vulnerabilities: SQL Injection + Hidden Admin Bypass + JWT Forgery
Author: Ashton Hicks | github.com/ashtonhickswv-sudo
"""

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import hashlib
import jwt
import datetime
import os

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # Intentionally weak

# --- Intentionally weak JWT secret (part of the challenge) ---
JWT_SECRET = "password1"

# --- Database setup ---
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY,
            flag TEXT,
            hint TEXT
        )
    """)

    # Seed users
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'guest', '084e0343a0486ff05530df6c705c8bb4', 'user')")      # MD5: guest
    c.execute("INSERT INTO users VALUES (2, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin')")    # MD5: password

    # Seed flags
    c.execute("DELETE FROM flags")
    c.execute("INSERT INTO flags VALUES (1, 'CTF{sql_1nj3ct10n_m4st3r}', 'Try logging in without a password...')")
    c.execute("INSERT INTO flags VALUES (2, 'CTF{jwt_f0rg3ry_unl0ck3d}', 'What if you could sign your own token?')")

    conn.commit()
    conn.close()


# ==============================
# ROUTES
# ==============================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        hashed = hashlib.md5(password.encode()).hexdigest()

        # VULNERABILITY 1: SQL Injection
        # No parameterized queries — raw string formatting
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
        try:
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            error = f"DB Error: {e}"
            user = None
        conn.close()

        if user:
            session["username"] = user[1]
            session["role"] = user[3]
            # Issue JWT token
            token = jwt.encode({
                "username": user[1],
                "role": user[3],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, JWT_SECRET, algorithm="HS256")
            session["token"] = token
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"], role=session["role"])


@app.route("/admin")
def admin():
    # VULNERABILITY 2: JWT forgery — trusts token without verifying secret properly
    token = request.args.get("token") or session.get("token")
    if not token:
        return render_template("admin.html", error="Access denied. No token provided.", flag=None)

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("role") == "admin":
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("SELECT flag FROM flags WHERE id=2")
            flag = c.fetchone()[0]
            conn.close()
            return render_template("admin.html", flag=flag, error=None, username=payload["username"])
        else:
            return render_template("admin.html", error="You are not an admin.", flag=None)
    except jwt.ExpiredSignatureError:
        return render_template("admin.html", error="Token expired.", flag=None)
    except Exception as e:
        return render_template("admin.html", error=f"Invalid token: {e}", flag=None)


@app.route("/flag1")
def flag1():
    """Only accessible if logged in via SQL injection"""
    if session.get("role") in ("user", "admin"):
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT flag FROM flags WHERE id=1")
        flag = c.fetchone()[0]
        conn.close()
        return render_template("flag.html", flag=flag, title="Flag 1 Captured!", hint="You bypassed authentication using SQL Injection.")
    return redirect(url_for("login"))


@app.route("/source-hint")
def source_hint():
    """Hints hidden in the page source — players must view-source"""
    return render_template("hint.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
