import secrets
import sqlite3
import html
import bcrypt
from flask import Flask, request, render_template, redirect, session, abort, make_response
from flask_bcrypt import Bcrypt
app = Flask(__name__)
con = sqlite3.connect("app.db", check_same_thread=False)
app.secret_key = secrets.token_hex(16)  # Required for session to work

@app.before_request
def set_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=session.get('csrf_token', ''))

@app.after_request
def add_security_headers(response):
    # Add Content-Security-Policy header
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    # Enable browser's XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    cur = con.cursor()
    if request.method == "GET":
        if request.cookies.get("session_token"):
            # No changes to this part
            res = cur.execute("SELECT username FROM users INNER JOIN sessions ON "
                              "users.id = sessions.user WHERE sessions.token = ?",
                              (request.cookies.get("session_token"),))
            user = res.fetchone()
            if user:
                return redirect("/home")

        return render_template("login.html")
    else:
        # Get the user by username only
        res = cur.execute("SELECT id, password FROM users WHERE username = ?",
                          (request.form["username"],))
        user = res.fetchone()

        # If user exists and password matches
        if user and bcrypt.check_password_hash(user[1], request.form["password"]):
            token = secrets.token_hex()
            # Use parameterized query
            cur.execute("INSERT INTO sessions (user, token) VALUES (?, ?)",
                        (user[0], token))
            con.commit()
            response = redirect("/home")
            # Set HttpOnly cookie to prevent JS access
            response.set_cookie("session_token", token, httponly=True)
            return response
        else:
            return render_template("login.html", error="Invalid username and/or password!")
@app.route("/")
@app.route("/home")
def home():
    cur = con.cursor()
    
    if request.cookies.get("session_token"):
        # Use parameterized query
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          "users.id = sessions.user WHERE sessions.token = ?", 
                         (request.cookies.get("session_token"),))
        user = res.fetchone()
        if user:
            # Use parameterized query
            res = cur.execute("SELECT message FROM posts WHERE user = ?", (user[0],))
            posts = res.fetchall()
            
            # Escape HTML in posts to prevent XSS
            escaped_posts = [(html.escape(post[0]),) for post in posts]
            
            return render_template("home.html", username=user[1], posts=escaped_posts)

    return redirect("/login")

@app.route("/posts", methods=["POST"])
def posts():
    # CSRF protection
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400)  # CSRF token invalid or missing
        
    cur = con.cursor()
    if request.cookies.get("session_token"):
        # Use parameterized query
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          "users.id = sessions.user WHERE sessions.token = ?", 
                         (request.cookies.get("session_token"),))
        user = res.fetchone()
        if user:
            # Sanitize message before storing
            safe_message = html.escape(request.form["message"])
            
            # Use parameterized query
            cur.execute("INSERT INTO posts (message, user) VALUES (?, ?)", 
                       (safe_message, user[0]))
            con.commit()
            return redirect("/home")

    return redirect("/login")

@app.route("/logout", methods=["GET"])
def logout():
    cur = con.cursor()
    if request.cookies.get("session_token"):
        # Use parameterized query
        res = cur.execute("SELECT users.id, username FROM users INNER JOIN sessions ON "
                          "users.id = sessions.user WHERE sessions.token = ?", 
                         (request.cookies.get("session_token"),))
        user = res.fetchone()
        if user:
            # Use parameterized query
            cur.execute("DELETE FROM sessions WHERE user = ?", (user[0],))
            con.commit()

    response = redirect("/login")
    response.set_cookie("session_token", "", expires=0)
    return response

if __name__ == '__main__':
    app.run(debug=True)