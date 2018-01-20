import uuid
import MySQLdb
import os
import base64
from flask import Flask, render_template, session, escape, request, json, jsonify, redirect, send_file, flash, current_app, Response
from werkzeug.utils import secure_filename, unescape
from functools import wraps
app = Flask(__name__, static_url_path='', static_folder='./web/static', template_folder='./web/templates')

db = MySQLdb.connect(host="localhost", user="root", passwd="password", db="VulnPracticeLabs")
cur = db.cursor()
cur.execute("SELECT * FROM users")

@app.route("/")
def index():
    if not session.get('logged_in'):
        if request.args.get('error') == "true":
            return render_template("index.html", login_error=True, reason=request.args.get('reason'))
        else:
            return render_template("index.html")
    else:
        return redirect('/login')

@app.route("/logout", methods = ['GET', 'POST'])
def logout():
    session.pop('logged_in')
    return redirect('/')

@app.route("/api/upload_file", methods = ['GET', 'POST'])
def upload_file():
    if session.get('logged_in'):
        if session.get('api_key'):
            if request.method == 'POST':
                if 'file' not in request.files:         # check if the post request has the file part
                    return jsonify({"error_msg": "FILE PARAMETER NOT SPECIFIED"})
                else:
                    uploaded_file = request.files['file']
                    # if user does not select file, browser also
                    # submit a empty part without filename
                    if uploaded_file.filename == '':
                        return jsonify({"error_msg": "FILE NAME NOT SPECIFIED"})
                    else:
                        original_filename = secure_filename(uploaded_file.filename)
                        extension = original_filename.split('.')[-1]
                        if '.' not in original_filename:
                            new_filename = uuid.uuid4().hex
                        else:
                            new_filename = uuid.uuid4().hex + '.' + extension
                        # Send Current Filename, Original File Name, and Download key to database
                        uploaded_file.save("./web/uploads/" + new_filename)
                        flash("Uploaded")
                        return redirect("/login")
            else:
                return jsonify({'error_msg': 'INVALID HTTP METHOD'})
        else:
            return jsonify({"error_msg": "INVALID DOWNLOAD KEY"})
    else:
        return jsonify({'error_msg': 'NOT LOGGED IN'})

@app.route("/api/file/<api_key>/<original_filename>/", methods = ['GET'])
def download_user_file(api_key, original_filename):
    if session.get('logged_in'):
        if api_key == session.get('api_key'):
                path = "./web/uploads/%s" % (original_filename)
                if os.path.exists(path):
                    return send_file(path, as_attachment=True)
                else:
                    return jsonify({"error_msg":"file does not exist"})
        else:
                return jsonify({"error_msg":"invalid api_key"})

@app.route("/message/", methods = ['GET'])
def error_page():
    title = request.args.get('title')
    message = request.args.get('message')
    color = request.args.get('color')
    return render_template("error.html", title=title, message=message, color=color)

def support_jsonp(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        callback = request.args.get('callback', False)
        if callback:
            content = str(callback) + '(' + str(f().data) + ')'
            return current_app.response_class(content, mimetype='text/html')
        else:
            return f(*args, **kwargs)
    return decorated_function

# SQL Injection / Bruteforce
@app.route("/login", methods = ['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('logged_in'):
            file_list = os.listdir('./web/uploads/')
            try:
                file_list.remove('.DS_Store')
            except:
                pass
            return render_template("authenticated.html", user_id=session.get('user_id'), username=session.get('username'), file_list=file_list, api_key=session.get('api_key'))
        else:
            return redirect('/?error=true')
    elif request.method == 'POST':
        login_query = cur.execute("SELECT * FROM users WHERE username = '" + request.form['username'] + "' AND password = '" + request.form['password'] +  "'")
        if login_query == True:
            session['logged_in'] = True
            session['username'] = request.form['username']
            cur.execute("SELECT api_key FROM users WHERE username ='" + request.form['username'] + "'")
            session['api_key'] = cur.fetchone()[0]
            cur.execute("SELECT id FROM users WHERE username ='" + request.form['username'] + "'")
            session['user_id'] = cur.fetchone()[0]
            db.commit()
            file_list = os.listdir('./web/uploads/')
            try:
                file_list.remove('.DS_Store')
            except:
                pass
            return render_template("authenticated.html", user_id=session.get('user_id'), username=session.get('username'), file_list=file_list, api_key=session.get('api_key'))
        else:
            user_exist = cur.execute("SELECT * FROM users WHERE username = '" + request.form['username'] + "'")
            if user_exist == True:
                return redirect('/?error=true&reason=Invalid Password!')
            else:
                return redirect('/?error=true&reason=User does not exist!')
    else:
        return redirect('/message/?message=Invalid HTTP Method!&color=red&title=Error!')

# Blind XSS
@app.route("/api/sendmessage/", methods = ['GET', 'POST'])
def send_message():
    if session.get('logged_in'):
        message = base64.b64encode(request.form['message'])
        from_user = session.get('username')
        to_user = request.form['account_username']
        if to_user != from_user:
            if cur.execute("SELECT * FROM users WHERE username = '" + to_user + "';"):
                cur.execute("SELECT * FROM messages")
                cur.execute("INSERT INTO messages (fromuser,message,touser) VALUES ('%s','%s','%s');" % (from_user, message, to_user))
                db.commit()
                return redirect('/message/?message=Message Sent!&color=black&title=Success!')
            else:
                return redirect('/message/?message=User doesn\'t exist!&color=red&title=Error!')
        else:
            return redirect('/message/?message=You can\'t send a message to yourself!&color=black&title=Error!')
    else:
        return redirect('/')

# Blind XSS
@app.route("/private/messages/", methods = ["GET"])
def priv_messages():
    vals = cur.execute("SELECT * FROM messages WHERE touser='" + session.get('username') + "';")
    msg_data = cur.fetchall()
    db.commit()
    return render_template("private_messages.html", my_username=session.get('username'), msg_data=msg_data,base64=base64)

# IDOR
@app.route("/private/delete/", methods = ["GET"])
def delete_priv_messages():
    if session.get("logged_in"):
        vals = cur.execute("DELETE FROM messages WHERE id=" + request.args.get("msg") + ";")
        msg_data = cur.fetchall()
        db.commit()
        return redirect("/private/messages/")
    else:
        return redirect('/message/?message=Error! Not logged in!&color=red&title=Error!')

# MySQL Injection
@app.route("/api/username/", methods = ['GET'])
def get_user_by_id():
    if session.get('logged_in'):
        if request.method == 'GET':
            try:
                cur.execute("SELECT username FROM users WHERE id ='" + request.args.get('id') + "'")
                username = cur.fetchone()[0]
                db.commit()
                return jsonify({"username":username})
            except Exception, e:
                return jsonify({"error_msg": str(e)})

# Blind MySQL Injection
@app.route("/api/id/", methods = ['GET'])
def get_id_by_user():
    if session.get('logged_in'):
        if request.method == 'GET':
            try:
                cur.execute("SELECT id FROM users WHERE username ='" + request.args.get('username') + "'")
                username = cur.fetchone()[0]
                db.commit()
                return jsonify({"username":username})
            except:
                return redirect('/message/?message=An error has occured!&color=red&title=Error!')
    
# Cross Site Request Forgery
@app.route("/api/password_change/", methods = ['GET'])
def password_change():
    if session.get('logged_in'):
        if request.method == 'GET':
            if request.args.get('password1') == request.args.get('password2'):
                cur.execute("UPDATE users SET password ='" + request.args.get('password1') + "' WHERE username = '" + session['username'] + "'")
                db.commit()
                return render_template("password_changed.html")
            else:
                return redirect('/message/?message=Passwords did not match!&color=red&title=Error!')
        else:
            return redirect('/message/?message=Invalid HTTP Method!&color=red&title=Error!')

# Open Redirect / XSS
@app.route('/redirect', methods=['GET'])
def url_redirection():
    if session.get('logged_in') == True:
        return render_template('redirect.html', url_redirect=request.args.get('url'))
    else:
        return redirect('/')

# Reflected File Download
@app.route("/api/userinfo/<filename>/", methods = ['GET'])
def jsonp_download(filename):
    if session.get('logged_in') != None:
        with open('/tmp/' + filename, "w") as userinfo_file:
            userinfo_file.write(request.args.get('callback') + '(' + json.dumps({"userid":session.get('user_id'),"username":session.get('username'),"api_key":session.get('api_key')}) + str(')'))
        return send_file('/tmp/' + secure_filename(filename), secure_filename(filename), as_attachment=True)
    else:
        return redirect('/message/?color=red&message=Error! \'callback\' parameter is missing!&color=red&title=Error!')

# XSSi / XSS
@app.route("/api/userinfo/", methods = ['GET'])
@support_jsonp
def jsonp_view():
    if session.get('logged_in'):
        if request.args.get('callback') != None:
            return jsonify({"userid":session.get('user_id'),"username":session.get('username'),"api_key":session.get('api_key')})
        else:
            return redirect('/message/?message=Error! \'callback\' parameter is missing!&color=red&title=Error!')
    else:
       return redirect('/message/?message=Error! Not logged in!&color=red&title=Error!')

# IDOR
@app.route("/api/api_key/", methods = ['GET'])
@support_jsonp
def my_api_key():
    if session.get('logged_in'):
        if request.args.get('id') != None:
            cur.execute("SELECT api_key FROM users WHERE id ='" + request.args.get('id') + "'")
            api_key = cur.fetchone()[0]
            db.commit()
            return jsonify({"api_key":api_key})
    else:
        return redirect('/message/?message=Error! Not logged in!&color=red&title=Error!')

# CORS Misconfiguration
@app.route("/api/userinfo/json/", methods = ['GET'])
def json_view():
    if session.get('logged_in'):
        origin = request.headers.get('Origin')
        if origin != None:
            resp = Response(json.dumps({"userid":session.get('user_id'),"username":session.get('username'),"api_key":session.get('api_key')}))
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Content-Type'] = 'application/json'
        else:
            resp = Response(json.dumps({"userid":session.get('user_id'),"username":session.get('username'),"api_key":session.get('api_key')}))
            resp.headers['Content-Type'] = 'application/json'
        return resp
    else:
             return redirect('/message/?message=Error! Not logged in!&color=red&title=Error!')
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SECRET_KEY'] = "lollolol-lolol-lololol-lolol-lolololol"  # Used for session generation
app.debug=False
app.run()
