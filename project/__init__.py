#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Module init file. Runs application."""

from flask import Flask, render_template
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from flask.ext.login import LoginManager
import random
import string
import re
import os


app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
# app.config.from_object(os.environ['APP_SETTINGS'])
db = SQLAlchemy(app)


# helpers
def random_str(N=10):
    """Return random string of length N."""
    return ''.join(random.SystemRandom().choice(
        string.ascii_uppercase + string.ascii_lowercase + string.digits
    ) for _ in range(N))


def is_email(email):
    """Validate that an email is syntactially correct."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False
    return True

# BLueprints
from project.users.views import users_blueprint

app.register_blueprint(users_blueprint, url_prefix='/users')

# Login bits
from project.models import User

login_manager.login_view = "users.login"
login_manager.login_message = "Please login to view that page."


@login_manager.user_loader
def load_user(user_id):
    """Load the logged in user for the LoginManager."""
    return User.query.filter(User.id == int(user_id)).first()


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    """Render 404 page template."""
    return render_template('404.html'), 404

@app.route("/")
def hello():
    return "Flask Template"
