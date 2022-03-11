
from flask import Blueprint, render_template, request, flash, session
import flask
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

from flask import redirect, url_for

auth = Blueprint('auth', __name__)

@auth.route('/')
def home():
    return render_template("home.html")

@auth.route('/logining', methods=['GET', 'POST'])
def logining():       
    if request.method == 'POST':
        session['email'] = request.form['email']
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')

                login_user(user, remember=True)
                return redirect(url_for('auth.plant'))
            else:
                flash('Incorrect password , try again', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html")


@auth.route('/logout')
def logout():
    logout_user()
    if 'email' in session:
        session.pop('email', None)
        return redirect (url_for('auth.home'))
    else:
        return redirect(url_for('auth.logining',))

@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(firstName) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')

            return redirect(url_for('auth.plant'))

    return render_template("signup.html")

@auth.route('/plant')
def plant():
    if 'email' in session:
        email = session['email']
        return render_template("plant.html", email=email)
    else:
        return redirect(url_for('auth.home'))
        return flash('Not Ready!', category='error')

@auth.route('/pot')
def pot():
    if 'email' in session:
        email = session['email']
        return render_template("pot.html", email=email)
    else:
        return redirect(url_for('auth.home'))
        return flash('Not Ready!', category='error')