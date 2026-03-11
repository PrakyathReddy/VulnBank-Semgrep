import os
import hashlib
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, flash, g

app = Flask(__name__)

# Vulnerability: Hardcoded secrets
app.secret_key = "supersecretkey123"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

DATABASE = "bank.db"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                balance    REAL NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                from_acct  INTEGER,
                to_acct    INTEGER,
                amount     REAL,
                ts         DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        # Seed data
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("alice", hashlib.md5(b"password1").hexdigest()),
            )
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("bob", hashlib.md5(b"password2").hexdigest()),
            )
            db.execute("INSERT INTO accounts (user_id, balance) VALUES (1, 5000.00)")
            db.execute("INSERT INTO accounts (user_id, balance) VALUES (2, 3200.00)")
            db.commit()
        except sqlite3.IntegrityError:
            pass  # already seeded


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    accounts = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    txns = db.execute(
        """
        SELECT t.*, a1.id as from_name, a2.id as to_name
        FROM transactions t
        LEFT JOIN accounts a1 ON t.from_acct = a1.id
        LEFT JOIN accounts a2 ON t.to_acct   = a2.id
        ORDER BY t.ts DESC LIMIT 10
        """
    ).fetchall()
    return render_template("dashboard.html", accounts=accounts, txns=txns)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        # Vulnerability: SQL Injection — user input concatenated directly into query
        hashed = hashlib.md5(password.encode()).hexdigest()
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{hashed}'"
        )
        user = db.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account/<int:account_id>")
def account_detail(account_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # Vulnerability: IDOR — no check that this account belongs to the logged-in user
    account = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()

    if not account:
        flash("Account not found.", "danger")
        return redirect(url_for("index"))

    owner = db.execute(
        "SELECT username FROM users WHERE id = ?", (account["user_id"],)
    ).fetchone()

    txns = db.execute(
        """
        SELECT * FROM transactions
        WHERE from_acct = ? OR to_acct = ?
        ORDER BY ts DESC
        """,
        (account_id, account_id),
    ).fetchall()

    return render_template("account.html", account=account, owner=owner, txns=txns)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()

    if request.method == "POST":
        from_id = int(request.form["from_account"])
        to_id = int(request.form["to_account"])
        amount = float(request.form["amount"])

        from_acct = db.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (from_id, session["user_id"]),
        ).fetchone()

        if not from_acct:
            flash("Source account not found or access denied.", "danger")
        elif from_acct["balance"] < amount:
            flash("Insufficient funds.", "danger")
        else:
            db.execute(
                "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                (amount, from_id),
            )
            db.execute(
                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                (amount, to_id),
            )
            db.execute(
                "INSERT INTO transactions (from_acct, to_acct, amount) VALUES (?, ?, ?)",
                (from_id, to_id, amount),
            )
            db.commit()
            flash(f"Transferred ${amount:.2f} successfully.", "success")
            return redirect(url_for("index"))

    my_accounts = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    all_accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template(
        "transfer.html", my_accounts=my_accounts, all_accounts=all_accounts
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    output = None
    if request.method == "POST":
        f = request.files.get("statement")
        if f:
            filename = f.filename
            save_path = os.path.join("static", "uploads", filename)
            f.save(save_path)

            # Vulnerability: Command Injection — filename passed unsanitized to shell
            result = subprocess.run(
                f"file {save_path}",
                shell=True,
                capture_output=True,
                text=True,
            )
            output = result.stdout or result.stderr
            flash("File uploaded.", "success")

    return render_template("upload.html", output=output)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token_sent = None
    if request.method == "POST":
        username = request.form["username"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user:
            # Vulnerability: Weak cryptography — MD5 used for security token
            token = hashlib.md5(username.encode()).hexdigest()
            token_sent = token
            flash(f"Reset token (would be emailed): {token}", "info")
        else:
            flash("Username not found.", "danger")

    return render_template("reset_password.html", token_sent=token_sent)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
