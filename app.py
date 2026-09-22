import os
import sqlite3
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==================================================
# APPLICATION SETTINGS
# ==================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-secret-key"
)

DATABASE = "school.db"


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


# ==================================================
# CREATE DATABASE TABLES
# ==================================================

def init_db():
    db = get_db()

    # ------------------------------
    # USERS
    # ------------------------------
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # ------------------------------
    # SUBJECTS
    # ------------------------------
    db.execute("""
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    # ------------------------------
    # GRADES
    # ------------------------------
    db.execute("""
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            prelim REAL,
            midterm REAL,
            finals REAL,
            UNIQUE(student_id, subject_id),
            FOREIGN KEY(student_id) REFERENCES users(id),
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        )
    """)

    # CREATE DEFAULT ADMIN
    admin = db.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if admin is None:
        db.execute(
            """
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
            """,
            ("admin", generate_password_hash("admin123"), "admin")
        )

    # DEFAULT SUBJECTS
    subjects = ["Mathematics", "Science", "English"]
    for subject in subjects:
        db.execute(
            "INSERT OR IGNORE INTO subjects (name) VALUES (?)",
            (subject,)
        )

    db.commit()
    db.close()


# ==================================================
# INITIALIZE DATABASE
# ==================================================
init_db()


# ==================================================
# GRADE COMPUTATION
# ==================================================
def calculate_final(prelim, midterm, finals):
    if prelim is None or midterm is None or finals is None:
        return None
    final_grade = (prelim + midterm + finals) / 3
    return round(final_grade, 2)


# ==================================================
# VALIDATE COLLEGE GRADE
# ==================================================
def read_grade(form, field, subject_id):
    field_name = f"{field}_{subject_id}"
    value = form.get(field_name, "").strip()

    if value == "":
        return None

    try:
        grade = float(value)
    except ValueError:
        raise ValueError("Please enter a valid number.")

    if grade < 1 or grade > 5:
        raise ValueError("Grades must be between 1.00 and 5.00.")

    return grade


# ==================================================
# LOGIN REQUIRED DECORATOR
# ==================================================
def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return decorated_function


# ==================================================
# ADMIN REQUIRED DECORATOR
# ==================================================
def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("student_dashboard"))
        return function(*args, **kwargs)
    return decorated_function


# ==================================================
# ROUTES
# ==================================================

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("register"))
        if not password:
            flash("Password is required.", "error")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for("register"))

        db = get_db()
        existing_user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:
            db.close()
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        db.execute(
            """
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
            """,
            (username, hashed_password, "student")
        )
        db.commit()
        db.close()

        flash("Registration successful. You can now login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        db.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("student_dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/student")
@login_required
def student_dashboard():
    if session.get("role") != "student":
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    subjects = db.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    grades = db.execute(
        "SELECT * FROM grades WHERE student_id = ?",
        (session["user_id"],)
    ).fetchall()
    db.close()

    grade_dictionary = {g["subject_id"]: g for g in grades}

    return render_template(
        "student_dashboard.html",
        subjects=subjects,
        grades=grade_dictionary,
        calculate_final=calculate_final
    )


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    students = db.execute(
        "SELECT id, username FROM users WHERE role = 'student' ORDER BY username"
    ).fetchall()
    subjects = db.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    db.close()

    return render_template(
        "admin_dashboard.html",
        students=students,
        subjects=subjects
    )


@app.route("/admin/add-subject", methods=["POST"])
@admin_required
def add_subject():
    subject_name = request.form.get("subject_name", "").strip()
    if not subject_name:
        flash("Subject name is required.", "error")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO subjects (name) VALUES (?)",
            (subject_name,)
        )
        db.commit()
        flash("Subject added successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Subject already exists.", "error")
    finally:
        db.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/grades/<int:student_id>", methods=["GET", "POST"])
@admin_required
def edit_grades(student_id):
    db = get_db()

    student = db.execute(
        "SELECT id, username FROM users WHERE id = ? AND role = 'student'",
        (student_id,)
    ).fetchone()

    if student is None:
        db.close()
        flash("Student not found.", "error")
        return redirect(url_for("admin_dashboard"))

    subjects = db.execute("SELECT * FROM subjects ORDER BY name").fetchall()

    if request.method == "POST":
        try:
            for subject in subjects:
                prelim = read_grade(request.form, "prelim", subject["id"])
                midterm = read_grade(request.form, "midterm", subject["id"])
                finals = read_grade(request.form, "finals", subject["id"])

                db.execute(
                    """
                    INSERT INTO grades (student_id, subject_id, prelim, midterm, finals)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(student_id, subject_id) DO UPDATE SET
                        prelim = excluded.prelim,
                        midterm = excluded.midterm,
                        finals = excluded.finals
                    """,
                    (student_id, subject["id"], prelim, midterm, finals)
                )

            db.commit()
            flash("Grades saved successfully.", "success")
        except ValueError as error:
            db.rollback()
            flash(str(error), "error")
        finally:
            db.close()

        return redirect(url_for("edit_grades", student_id=student_id))

    existing_grades = db.execute(
        "SELECT * FROM grades WHERE student_id = ?",
        (student_id,)
    ).fetchall()
    db.close()

    grade_dictionary = {g["subject_id"]: g for g in existing_grades}

    return render_template(
        "edit_grades.html",
        student=student,
        subjects=subjects,
        grades=grade_dictionary,
        calculate_final=calculate_final
    )


@app.route("/health")
def health():
    return "OK", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)