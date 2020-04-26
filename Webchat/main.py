from functools import wraps

from flask import Flask
from flask import render_template, request, redirect, url_for, jsonify, session, make_response
from user import User
import json

app = Flask(__name__)
app.config["SECRET_KEY"] = "SxOW8IKSGVShQD6BXtQzMA"

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if not token or not User.verifyToken(token):
            return redirect('/login')
        return func(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    token = request.cookies.get('token')
    user_id = session.get("user_id")
    if token:
        username = User.find_name_by_id(user_id)
        return render_template('index.html', token=token, username=username)
    else:
        return render_template('index.html', token=token)

@app.route('/profile')
def profile():
    token = request.cookies.get('token')
    if token:
        user_id = session.get("user_id")
        username = User.find_name_by_id(user_id)
        email = User.find_email_by_id(user_id)
        address = User.find_address_by_id(user_id)
        mobile = User.find_mobile_by_id(user_id)
        return render_template('profile.html', 
                                username=username, 
                                email = email, 
                                address = address, 
                                mobile = mobile,
                                user_id = user_id)
                                
    else:
        return redirect('/login')

@app.route('/<int:id>/edit', methods=['GET', 'POST'])
def edit_profile(id):
    user = User.find_user_by_id(id)
    if request.method == "GET":
        return render_template('edit_profile.html', user = user)
    elif request.method == "POST":
        user.email = request.form['email']
        user.name = request.form['name'] 
        user.address = request.form['address'] 
        user.mobile = request.form['mobile'] 
        user.save()
        return redirect('/profile')

@app.route('/search', methods=['GET', 'POST'])
def search_user():
    if request.method == 'GET':
        return render_template('search.html')
    elif request.method == "POST":
        email = request.form['email']
        if User.find(email) == False:
            username = "This user doesn't exists"
        else:
            user2 = User.find(email)
            username = user2.name
        return redirect(url_for('follow', username=username, id=user2.id))

@app.route('/<int:id>/follow', methods=['GET', 'POST'])
def follow(id):
    user2 = User.find_user_by_id(id)
    # token = request.cookies.get('token')
    user_id = session.get("user_id")
    user = User.find_user_by_id(user_id)
    if request.method == 'GET':
        return render_template('follow.html', user2 = user2, user = user)
    elif request.method == 'POST':
        user1 = User.find_user_by_id(user_id)
        if user1.check_follow(user2.id) == False:
            user1.follow(user2.id)
        return redirect(url_for('follow', id=user2.id))
        





@app.route('/register', methods=["GET", "POST"])
def register():
    token = request.cookies.get('token')
    if not token or not User.verifyToken(token):
        if request.method == 'GET':
            return render_template('register.html')
        elif request.method == 'POST':
            info = (
                None,
                request.form['email'],
                User.hashPassword(request.form['password']),
                request.form['name'],
                request.form['address'],
                request.form['mobile']
            )
            User(*info).create()
            return redirect('/')
    else:
        return redirect('/')


@app.route('/login', methods=["GET", "POST"])
def login():
    token = request.cookies.get('token')
    if not token:
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            data = json.loads(request.data.decode('ascii'))
            email = data['email']
            password = data['password']
            user = User.find(email)
            if not user or not user.verifyPassword(password):
                return jsonify({'token': None})
            token = user.generateToken()
            session["user_id"] = user.id
            return jsonify({'token': token.decode('ascii')})
    else:
        return redirect('/')

@app.route('/logout', methods=["GET"])
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('token', '', expires=0)
    session.pop("user_id")
    return resp

if __name__ == '__main__':
    app.run(debug=True)      
