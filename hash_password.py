import sqlite3
from flask import Flask
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Connect to the database
con = sqlite3.connect("app.db")
cur = con.cursor()

# Get alice's current plaintext password
res = cur.execute("SELECT id, password FROM users WHERE username = 'alice'")
user = res.fetchone()

if user:
    user_id, plaintext_password = user

    # Hash the current password
    hashed_password = bcrypt.generate_password_hash(plaintext_password).decode('utf-8')

    # Update alice's password in the database
    cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
    con.commit()
    print(f"Updated alice's password to hashed version.")
    print(f"The plaintext password is still: {plaintext_password}")
else:
    print("User 'alice' not found.")

con.close()