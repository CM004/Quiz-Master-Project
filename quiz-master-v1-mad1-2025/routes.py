from flask import render_template, request, flash, redirect, url_for, session
from app import app, db
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def enforce_navigation_rules():
    """Ensure users navigate only as per rules and remember sessions."""
    user_exists = User.query.first() is not None
    logged_in = 'user_id' in session

    # Redirect new users to register
    if not user_exists and request.endpoint not in ['register', 'static']:
        return redirect(url_for('register'))

    # Prevent access to login without registration
    if request.endpoint == 'login' and not user_exists:
        flash("You need to register first.")
        return redirect(url_for('register'))

    # Prevent access to index without login
    if request.endpoint == 'index' and not logged_in:
        flash("Please login first.")
        return redirect(url_for('login'))

    # Prevent registered users from accessing register again
    if request.endpoint == 'register' and logged_in:
        flash("You are already logged in.")
        return redirect(url_for('index'))

@app.route('/')
@auth_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Invalid username.')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Invalid password.')
            return redirect(url_for('login'))

        session['user_id'] = user.id  # Maintain session
        flash("Login successful.")
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        fullname = request.form['fullname']
        qualification = request.form['qualification']
        dob_str = request.form['dob']

        if not all([username, password, confirm_password, fullname, qualification, dob_str]):
            flash('All fields are required!')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))

        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                fullname=fullname,
                qualification=qualification,
                dob=dob
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/profile')
@auth_required
def profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.')
        return redirect(url_for('logout'))
    return render_template('profile.html', user=user)

@app.route('/profile', methods=['POST'])
@auth_required
def profile_post():
    username = request.form['username']
    cpassword = request.form['cpassword']
    password = request.form['password']
    name = request.form['name']

    if not username or not cpassword or not name:
        flash('All fields are required!')
        return redirect(url_for('profile'))
    
    user = User.query.get(session['user_id'])
    
    if not check_password_hash(user.password, cpassword):
        flash('Current password is incorrect!')
        return redirect(url_for('profile'))
    
    # Check if username is being changed
    if username != user.username:
        # Check if new username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return redirect(url_for('profile'))
    
    # Update user information
    user.username = username
    user.fullname = name
    if password:  # Only update password if a new one is provided
        user.password = generate_password_hash(password)
    
    try:
        db.session.commit()
        flash('Profile updated successfully!')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating your profile.')
    
    return redirect(url_for('profile'))

@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')  # Clears session on logout
    flash("You have been logged out.")
    return redirect(url_for('login'))