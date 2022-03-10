from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class User(db.Model, UserMixin):
    ## Need to Set Primary Key (Unique)
    id = db.Column(db.Integer, primary_key = True)

    ## Set E-mail >> Unique
    email = db.Column(db.String(150), unique=True)

    password = db.Column(db.String(150))
    firstName = db.Column(db.String(150))
    notes = db.relationship('Note')

# Each User have multiple Note (Foreign Key) ==> Lower-case class name
# (1-to-Many) ==> Recommend to use Primary Key
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True),default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
