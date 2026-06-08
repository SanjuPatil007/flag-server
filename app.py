import hashlib, os, sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, g

app = Flask(__name__)

SALT       = os.environ.get("SECRET_SALT", "")
DB_PATH    = os.environ.get("DB_PATH", "scores.db")
CTF_NAME   = os.environ.get("CTF_NAME", "ScalerBank CTF")
CTF_OPEN   = os.environ.get("CTF_OPEN", "1")   # set to "0" to close submissions

CHALLENGES = [
    ("vault",   "Vault Access",      5),
    ("reflect", "Search & Steal",    6),
    ("jwt",     "Unsigned Access",   6),
    ("xxe",     "Import Statement",  6),
    ("cmdi",    "Statement Mailer",  8),
    ("csrf",    "Email Hijack",      9),
    ("ssti",    "Welcome Card",      8),
    ("reset",   "Self Service",      7),
    ("domxss",  "Account Nickname", 12),
    ("blind",   "Balance Check",    13),
]
MAX_SCORE = sum(p for _, _, p in CHALLENGES)


# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(_):
    db = getattr(g, "_db", None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS submissions (
                id          INTEGER PRIMARY KEY,
                student_id  TEXT    NOT NULL,
                score       INTEGER NOT NULL DEFAULT 0,
                detail      TEXT,
                submitted_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_student ON submissions(student_id);
        """)
        db.commit()


# ── FLAG LOGIC ────────────────────────────────────────────────────────────────

def expected_flag(student_id, cid):
    h = hashlib.sha256(f"{student_id}_{cid}_{SALT}".encode()).hexdigest()[:8]
    return f"FLAG{{{cid}_{h}}}"

def validate_submission(student_id, form):
    results = []
    total   = 0
    for cid, name, pts in CHALLENGES:
        submitted = form.get(cid, "").strip()
        correct   = bool(submitted) and submitted.lower() == expected_flag(student_id, cid).lower()
        if correct:
            total += pts
        results.append({
            "cid":       cid,
            "name":      name,
            "pts":       pts,
            "submitted": submitted,
            "correct":   correct,
        })
    return results, total


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           challenges=CHALLENGES,
                           ctf_name=CTF_NAME,
                           ctf_open=CTF_OPEN == "1")

@app.route("/submit", methods=["POST"])
def submit():
    if CTF_OPEN != "1":
        return render_template("closed.html", ctf_name=CTF_NAME)

    sid = request.form.get("student_id", "").strip().upper()
    if not sid:
        return render_template("index.html",
                               challenges=CHALLENGES,
                               ctf_name=CTF_NAME,
                               ctf_open=True,
                               error="Roll number is required.")

    results, total = validate_submission(sid, request.form)

    # Store / update — always takes the latest submission
    detail = ",".join(r["cid"] for r in results if r["correct"])
    db = get_db()
    db.execute("""
        INSERT INTO submissions (student_id, score, detail, submitted_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(student_id) DO UPDATE SET
            score        = excluded.score,
            detail       = excluded.detail,
            submitted_at = excluded.submitted_at
    """, (sid, total, detail, datetime.now().isoformat()))
    db.commit()

    return render_template("results.html",
                           sid=sid,
                           results=results,
                           total=total,
                           max_score=MAX_SCORE,
                           ctf_name=CTF_NAME)

@app.route("/leaderboard")
def leaderboard():
    rows = get_db().execute("""
        SELECT student_id, score, submitted_at
        FROM   submissions
        ORDER  BY score DESC, submitted_at ASC
    """).fetchall()
    return render_template("leaderboard.html",
                           rows=rows,
                           max_score=MAX_SCORE,
                           ctf_name=CTF_NAME)

@app.route("/health")
def health():
    return "ok", 200


# ── STARTUP ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
