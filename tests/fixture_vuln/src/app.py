import os, pickle, yaml, subprocess
from flask import Flask, request

app = Flask(__name__)

OPENAI_API_KEY = "sk-proj-AbCdEf0123456789AbCdEf0123456789"
aws_secret_access_key = "wJalrXUtnFEMIabcdEXAMPLEKEYabcdEXAMPLE123"
password = "h8Fk2zQw9bYt3Lp0"

@app.route("/u")
def user():
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return open(request.args.get("path")).read()

@app.route("/load")
def load():
    data = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    subprocess.run("ls " + request.args.get("d"), shell=True)
    return str(data)

if __name__ == "__main__":
    app.run(debug=True)
