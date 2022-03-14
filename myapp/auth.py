
from flask import Blueprint, render_template, request, flash, session
import flask
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

from flask import redirect, url_for

### google authentication ###

import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

### end google authentication ###

auth = Blueprint('auth', __name__)

#### route google authentication ###

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# You need to modify here
GOOGLE_CLIENT_ID = "601875999460-cii7pf3fauia8hdk7dsnv4idrregvvqp.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@auth.route("/logined")
def logined():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@auth.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    session["pic"] = id_info.get("picture")
    return redirect('/')

### end route google authentication ###

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
        session.clear()
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

@auth.route('/customer')
def customer():
    if 'email' in session:
        email = session['email']
        return render_template("custo.html", email=email)
    else:
        return redirect(url_for('auth.home'))
        return flash('Not Ready!', category='error')