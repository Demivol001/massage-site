"""
Сайт массажного салона «Лотос»: Flask + SQLite.

Как читать этот файл (сверху вниз):
1. Настройки и подключение к БД
2. Создание таблиц и стартовых данных (init_db)
3. Защита: кто может заходить на какие страницы
4. Страницы (routes): регистрация, вход, главная, запись, мои записи, админ
"""
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (Flask, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "salon.db"

app = Flask(__name__)
# Секретный ключ подписывает cookie с сессией. В реальном проекте он должен быть случайным и скрытым.
app.secret_key = "dev-secret-change-me"

# Адрес и время работы салона (меняйте здесь — обновится на всех страницах)
SALON = {
    "name": "Лотос",
    "address": "г. Москва, ул. Тверская, д. 15, 2 этаж",
    "phone": "+7 (495) 123-45-67",
    "hours": "Ежедневно 10:00 – 20:00",
}
# Слоты записи: каждый час с 10:00 до 19:00 (последний сеанс начинается в 19:00)
SLOTS = [f"{h:02d}:00" for h in range(10, 20)]


# ---------------------------------------------------------------- 1. БАЗА ДАННЫХ
def get_db():
    """Одно подключение к БД на запрос. row_factory позволяет писать row['name']."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------- 2. ТАБЛИЦЫ
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            duration INTEGER NOT NULL,      -- минуты
            price INTEGER NOT NULL          -- рубли
        );
        CREATE TABLE IF NOT EXISTS specialists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            bio TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            service_id INTEGER NOT NULL REFERENCES services(id),
            specialist_id INTEGER NOT NULL REFERENCES specialists(id),
            day TEXT NOT NULL,              -- дата 'YYYY-MM-DD'
            time TEXT NOT NULL,             -- время 'HH:MM'
            created_at TEXT NOT NULL,
            -- Один мастер не может быть записан на одно и то же время дважды:
            UNIQUE (specialist_id, day, time)
        );
        """
    )
    # Стартовые данные — только если таблицы пустые
    if db.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO services (name, description, duration, price) VALUES (?,?,?,?)",
            [
                ("Классический массаж", "Расслабляет мышцы, снимает усталость и напряжение во всём теле.", 60, 3500),
                ("Массаж спины и шеи", "Помогает при «сидячей» работе: снимает зажимы и головные боли.", 40, 2500),
                ("Антицеллюлитный массаж", "Интенсивная работа с проблемными зонами, улучшает тонус кожи.", 60, 4000),
                ("Тайский массаж", "Растяжка и глубокая проработка мышц, возвращает гибкость.", 90, 5500),
                ("Лимфодренажный массаж", "Мягкая техника: уменьшает отёки и ускоряет обмен веществ.", 60, 4200),
                ("Расслабляющий с маслами", "Тёплые ароматические масла, медленный ритм, полное расслабление.", 75, 4800),
            ],
        )
    if db.execute("SELECT COUNT(*) FROM specialists").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO specialists (name, role, bio) VALUES (?,?,?)",
            [
                ("Анна Соколова", "Массажист-реабилитолог", "Стаж 12 лет. Работает со спиной, шеей и осанкой."),
                ("Дмитрий Орлов", "Спортивный массажист", "Стаж 9 лет. Восстановление после тренировок и травм."),
                ("Мария Ким", "Мастер тайского массажа", "Стаж 7 лет. Обучалась в Бангкоке, любит глубокую растяжку."),
            ],
        )
    # Администратор по умолчанию (СМЕНИТЕ пароль в реальном проекте!)
    if db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (name, phone, email, password_hash, is_admin) VALUES (?,?,?,?,1)",
            ("Администратор", "+7 000 000-00-00", "admin@lotos.local", generate_password_hash("admin123")),
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------- 3. ЗАЩИТА СТРАНИЦ
@app.before_request
def load_user_and_require_login():
    """Выполняется перед КАЖДЫМ запросом.
    Достаём пользователя из сессии; если не вошёл — отправляем на регистрацию."""
    g.user = None
    if "user_id" in session:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if g.user is None:          # пользователя удалили из БД
            session.clear()
    open_pages = {"register", "login", "static"}
    if g.user is None and request.endpoint not in open_pages:
        return redirect(url_for("register"))


def admin_required(view):
    """Декоратор: пускает на страницу только администратора."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None or not g.user["is_admin"]:
            flash("Эта страница только для администратора.", "error")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_globals():
    """Переменные, доступные во всех шаблонах."""
    return {"salon": SALON, "user": g.get("user")}


# ---------------------------------------------------------------- 4. СТРАНИЦЫ
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("home"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        digits = "".join(c for c in phone if c.isdigit())

        if not name or not email or not password:
            flash("Заполните все поля.", "error")
        elif len(digits) < 10:
            flash("Введите корректный номер телефона.", "error")
        elif len(password) < 6:
            flash("Пароль должен быть не короче 6 символов.", "error")
        else:
            db = get_db()
            try:
                # Пароль храним только в виде хэша — сам пароль в БД не лежит
                cur = db.execute(
                    "INSERT INTO users (name, phone, email, password_hash) VALUES (?,?,?,?)",
                    (name, phone, email, generate_password_hash(password)),
                )
                db.commit()
                session["user_id"] = cur.lastrowid
                flash(f"Добро пожаловать, {name}!", "ok")
                return redirect(url_for("home"))
            except sqlite3.IntegrityError:   # email уже есть (UNIQUE)
                flash("Пользователь с таким email уже зарегистрирован.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            return redirect(url_for("admin" if row["is_admin"] else "home"))
        flash("Неверный email или пароль.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    db = get_db()
    services = db.execute("SELECT * FROM services").fetchall()
    specialists = db.execute("SELECT * FROM specialists").fetchall()
    return render_template("home.html", services=services, specialists=specialists)


@app.route("/api/slots")
def api_slots():
    """Отдаёт JSON: какие часы у мастера в выбранный день уже заняты.
    Страница записи запрашивает это через JavaScript (fetch)."""
    specialist_id = request.args.get("specialist", type=int)
    day = request.args.get("day", "")
    rows = get_db().execute(
        "SELECT time FROM bookings WHERE specialist_id = ? AND day = ?", (specialist_id, day)
    ).fetchall()
    return jsonify({"slots": SLOTS, "taken": [r["time"] for r in rows]})


@app.route("/book", methods=["GET", "POST"])
def book():
    db = get_db()
    services = db.execute("SELECT * FROM services").fetchall()
    specialists = db.execute("SELECT * FROM specialists").fetchall()
    today = date.today()

    if request.method == "POST":
        service_id = request.form.get("service", type=int)
        specialist_id = request.form.get("specialist", type=int)
        day = request.form.get("day", "")
        time = request.form.get("time", "")

        # Проверяем всё, что пришло от пользователя (никогда не доверяем форме!)
        try:
            day_obj = datetime.strptime(day, "%Y-%m-%d").date()
        except ValueError:
            day_obj = None

        if not (service_id and specialist_id and day_obj and time):
            flash("Выберите услугу, мастера, дату и время.", "error")
        elif day_obj < today or day_obj > today + timedelta(days=60):
            flash("Запись возможна на ближайшие 60 дней.", "error")
        elif time not in SLOTS:
            flash("Выберите время из списка.", "error")
        elif day_obj == today and time <= datetime.now().strftime("%H:%M"):
            flash("Это время уже прошло.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO bookings (user_id, service_id, specialist_id, day, time, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (g.user["id"], service_id, specialist_id, day, time,
                     datetime.now().strftime("%Y-%m-%d %H:%M")),
                )
                db.commit()
                flash("Вы записаны! Ждём вас в салоне.", "ok")
                return redirect(url_for("my_bookings"))
            except sqlite3.IntegrityError:
                flash("Это время только что заняли. Выберите другое.", "error")

    return render_template(
        "book.html", services=services, specialists=specialists,
        min_day=today.isoformat(), max_day=(today + timedelta(days=60)).isoformat(),
        preselect_service=request.args.get("service", type=int),
    )


BOOKING_SQL = """
    SELECT b.id, b.day, b.time, b.created_at,
           s.name AS service, s.duration, s.price,
           sp.name AS specialist,
           u.name AS client, u.phone AS phone
    FROM bookings b
    JOIN services s    ON s.id  = b.service_id
    JOIN specialists sp ON sp.id = b.specialist_id
    JOIN users u       ON u.id  = b.user_id
"""


@app.route("/my")
def my_bookings():
    rows = get_db().execute(
        BOOKING_SQL + " WHERE b.user_id = ? ORDER BY b.day, b.time", (g.user["id"],)
    ).fetchall()
    return render_template("my.html", bookings=rows, today=date.today().isoformat())


@app.route("/my/cancel/<int:booking_id>", methods=["POST"])
def cancel_booking(booking_id):
    db = get_db()
    # user_id в условии — чтобы нельзя было отменить чужую запись
    db.execute("DELETE FROM bookings WHERE id = ? AND user_id = ?", (booking_id, g.user["id"]))
    db.commit()
    flash("Запись отменена.", "ok")
    return redirect(url_for("my_bookings"))


@app.route("/admin")
@admin_required
def admin():
    day = request.args.get("day", "")
    sql, params = BOOKING_SQL, []
    if day:
        sql += " WHERE b.day = ?"
        params.append(day)
    rows = get_db().execute(sql + " ORDER BY b.day, b.time", params).fetchall()

    # Группируем записи по датам: {'2026-11-06': [запись, запись], ...}
    grouped = {}
    for r in rows:
        grouped.setdefault(r["day"], []).append(r)

    db = get_db()
    stats = {
        "total": db.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
        "upcoming": db.execute("SELECT COUNT(*) FROM bookings WHERE day >= ?", (date.today().isoformat(),)).fetchone()[0],
        "clients": db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 0").fetchone()[0],
    }
    return render_template("admin.html", grouped=grouped, stats=stats, day=day, today=date.today().isoformat())


@app.route("/admin/delete/<int:booking_id>", methods=["POST"])
@admin_required
def admin_delete(booking_id):
    db = get_db()
    db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    flash("Запись удалена.", "ok")
    return redirect(request.referrer or url_for("admin"))


# Фильтр для шаблонов: '2026-11-06' -> '6 ноября 2026, пятница'
MONTHS = ["января", "февраля", "марта", "апреля", "мая", "июня", "июля",
          "августа", "сентября", "октября", "ноября", "декабря"]
WEEKDAYS = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"]


@app.template_filter("rudate")
def rudate(value):
    d = datetime.strptime(value, "%Y-%m-%d").date()
    return f"{d.day} {MONTHS[d.month - 1]} {d.year}, {WEEKDAYS[d.weekday()]}"


init_db()

if __name__ == "__main__":
    app.run(debug=True)
