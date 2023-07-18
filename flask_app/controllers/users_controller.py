from flask_app import app
from flask import flash, render_template, request, redirect, session
from flask_app.models.user_model import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

#table_name/id/action

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/users/dashboard')
    return render_template('index.html')

@app.route('/users/register', methods=['POST'])
def register():
    if not User.is_valid(request.form):
        return redirect('/')
    hashed_pass = bcrypt.generate_password_hash(request.form['password'])
    data = {
        **request.form,
        'password':hashed_pass,
        'cpass':hashed_pass
    }
    logged_user_id = User.create(data)
    session['user_id'] = logged_user_id
    
    # return render_template('dashboard.html', logged_user = User.get_by_id({'id':logged_user_id}))

    return redirect('/users/dashboard')


@app.route('/users/login', methods=['POST'])
def login():
    data = {
        'email': request.form['email']
    }
    potential_user = User.get_by_email(data)
    if not potential_user:
        flash('Invalid credentials','log')
        return redirect('/')
    if not bcrypt.check_password_hash(potential_user.password, request.form['password']):
        flash('Invalid credentials','log')
        return redirect('/')
    session['user_id'] = potential_user.id
    return redirect('/users/dashboard')

@app.route('/users/logout')
def logout():
    del session['user_id']
    return redirect('/')

@app.route('/users/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    data = {
        'id': session['user_id']
        }
    logged_user = User.get_by_id(data)
    return render_template('dashboard.html',logged_user=logged_user)