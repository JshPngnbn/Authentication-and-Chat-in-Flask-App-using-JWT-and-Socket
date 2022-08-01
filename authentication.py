# simple login authentication with route
from flask import Flask, jsonify, make_response, request, render_template, session, redirect
import jwt
from datetime import datetime, timedelta
from functools import wraps
import time
import socket


app = Flask(__name__)


app.config['SECRET_KEY'] = 'YOU_SECRET_KEY'


# requiring token in '/auth' route e.g ('http://127.0.0.1:5000/auth?token=yourtoken)


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Add token to the url/login to get your token'}), 401
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'Message': 'Invalid token/token expired'}), 401
        return func(*args, **kwargs)
    return decorated

# landing page with simple html template


@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'logged in currently. You can use chat, just go to http://127.0.0.1:5000/chat and check your terminal'

# a public route for sending messages. check terminal


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = '127.0.0.1'
port = 7634


@app.route('/chat')
def public():
    if not session.get('logged_in'):
        return redirect("http://127.0.0.1:5000/")
    else:
        s.connect((host, port))
        while True:
            print("waiting for response")
            message = s.recv(1024)
            print("message from server: ", message.decode())
            message = input("send message to server: ")
            s.send(message.encode())


# route with token needed e.g ('http://127.0.0.1:5000/auth?token=yourtoken)


@app.route('/auth')
@token_required
def auth():
    token = request.args.get('token')
    return jsonify({'Token':   jwt.decode(
        token, app.config['SECRET_KEY'], algorithms=['HS256'])})

# token expiration time 30 seconds


jwt_valid_seconds = 40
expiry_time = round(time.time()) + jwt_valid_seconds

# once login, directed to '/login' route and return encrypted token


@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '123456':
        session['logged_in'] = True

        token = jwt.encode({
            'user': request.form['username'],
            "exp": expiry_time,
        },
            app.config['SECRET_KEY'])
        return jsonify({'Your token': token})
    else:
        return make_response('Unable to verify', 401, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})


if __name__ == "__main__":
    app.run()
