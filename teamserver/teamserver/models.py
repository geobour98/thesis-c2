from flask_login import UserMixin
from datetime import datetime, timedelta
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(50))
    password = db.Column(db.String(100))

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String(20))
    is_fetched = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=2))

    def __repr__(self):
        return f'<Task {self.id} - {self.command}>'