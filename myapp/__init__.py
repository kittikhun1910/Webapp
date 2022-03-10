from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path

from flask_login import*

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'qwerty asdfgh zxcvbn'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .auth import auth

    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Note
    create_database(app)
    return app

def create_database(app):
    if not path.exists('myapp' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')
