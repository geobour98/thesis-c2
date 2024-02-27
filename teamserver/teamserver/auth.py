from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template("login.html", active_page='login')

@auth.route('/login', methods = ["POST"])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        flash('Invalid username or password!')
        return redirect(url_for('auth.login'))

    login_user(user)
    return redirect(url_for('main.tasks'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
