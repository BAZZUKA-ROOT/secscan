import os
from flask import Flask, request
app = Flask(__name__)
API_KEY = os.environ["API_KEY"]
PLACEHOLDER = "changeme"
def user(uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
app.run(debug=False)
