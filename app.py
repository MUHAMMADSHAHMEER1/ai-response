import json
import openAIFunc as OF
import codeChecker as cc
from datetime import timedelta
import hashlib
from flask import Flask, render_template, request, jsonify, redirect, make_response
import mysql.connector
from flask_jwt_extended import jwt_required, create_access_token
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
import os
import smtplib
from email.mime.text import MIMEText
import random
import string

app = Flask(__name__)

app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_SECRET_KEY"] = "wei9wms332xczap0uh1mkl3214dncvs435m"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

jwt = JWTManager(app)

current_user = None

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="shameer_project"
)

@app.route('/')
def index():
    return render_template('index.html')

def sendEmail(email):
    sender = 'shahmeer1475@gmail.com'
    password = "vtlc hhya ctec ndvj"
    letters = string.ascii_letters
    OTPCode = ''.join(random.choice(letters) for _ in range(6))

    msg = MIMEText("Your OTP is " + OTPCode)
    msg['Subject'] = "Shameer's project OTP"
    msg['From'] = 'shahmeer1475@gmail.com'
    msg['To'] = email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(sender, password)
        smtp_server.sendmail(sender, email, msg.as_string())
    print("Message sent!")

@app.route('/home')
@jwt_required()
def home():
    return render_template('main.html')

@app.route('/history')
def history_page():
    cursor = conn.cursor()
    query = "SELECT user_query, response, insertedat FROM history WHERE username LIKE %s ORDER BY insertedat DESC"

    cursor.execute(query, (current_user,))
    results = cursor.fetchall()

    # Close cursor and database connection
    cursor.close()

    # Pass the sorted results to the template rendering function
    for row in results:
        print(row)
    return render_template('history.html', results=results)

@app.route('/login_action', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        auth = request.json
        if not auth or not auth.get('username') or not auth.get('password'):

            return make_response(
                'Could not verify',
                401,
                {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
            )

        else:
            username = auth.get('username')
            password = auth.get('password')
            cursor = conn.cursor()
            cursor.execute("SELECT salt, hashed_password FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()

            if user_data:
                stored_salt, stored_password = user_data
                entered_password_hashed = hash_password(password, stored_salt)

                if stored_password == entered_password_hashed:
                    global current_user  # Access the global variable
                    current_user = username
                    response = jsonify({"msg": "login successful"})
                    access_token = create_access_token(identity="LIME")
                    set_access_cookies(response, access_token)
                    cursor.close()

                    return response

        return make_response(
            'Could not verify',
            403,
            {'WWW-Authenticate': 'Basic realm ="Wrong Username or Password !!"'}
        )


# Sign-up route
@app.route('/SignUp_action', methods=['POST'])
def SignUpAction():
    if request.method == 'POST':
        auth = request.json
        if not auth or not auth.get('username') or not auth.get('password') or not auth.get('email') or not auth.get('fullname'):
            return make_response('Could not verify', 401)
        else:
            username = auth.get('username')
            password = auth.get('password')  # Issue might be here
            email = auth.get('email')
            fullname = auth.get('fullname')

            if len(password) < 8:  # Issue is with this line
                return make_response('Password must be at least 8 characters long', 410)

            salt = os.urandom(32)
            hashed_password = hash_password(password, salt)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM `users` WHERE `username` = %s OR `email_address` = %s", (username, email))
            existing_user = cursor.fetchone()

            if existing_user:
                return make_response('Username or email already exists', 409)

            cursor.execute(
                "INSERT INTO `users` (`username`, `full_name`, `salt`, `hashed_password`, `email_address`) VALUES (%s, %s, %s, %s, %s)",
                (username, fullname, salt, hashed_password, email))
            conn.commit()
            response = jsonify({"msg": "Signup successful"})
            global current_user
            current_user = username
            return response

@app.route('/Register')
def SignUp():
    return render_template('SignUp.html')

@app.route('/ChatWithGPT', methods=['POST'])
def chatwithGPT():
    data = request.get_json()
    inputText = data['input']
    response = OF.chat_with_gpt(inputText)
    print(response)
    cursor = conn.cursor()
    insert_query = "INSERT INTO history (username, user_query, response, insertedat) VALUES (%s, %s, %s, NOW())"
    cursor.execute(insert_query, (current_user, inputText, response))
    conn.commit()

    return jsonify({'answer': response})

@app.route('/report')
@jwt_required()
def report():
    # Retrieve the 'answer' parameter from the query string
    answer = request.args.get('answer')
    return render_template('report.html', answer=answer)

@app.route('/checkCode', methods=['POST'])
def CheckCode():
    data = request.get_json()
    inputText = data['input']
    response = cc.parse_sample(inputText)
    print(response)
    return jsonify({'answer': response})

def hash_password(password, salt):
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
    return hashed_password

@app.route('/logout')
def logout():
    global current_user
    current_user = None
    return render_template('index.html')

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return redirect('/')

if __name__ == '__main__':
    app.run()
