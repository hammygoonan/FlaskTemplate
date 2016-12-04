#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Main app entry point."""

import random
import string
import re
import os

from flask import Flask, send_from_directory, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from .flask_mailgun.flask_mailgun import Mailgun
from .errors import ErrorHandler

app = Flask(__name__)
app.config.from_object(os.environ['PROJECT_SETTINGS'])
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
mailgun = Mailgun(app)

if not app.debug:
    ErrorHandler(app)


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


from .users.views import users_blueprint
from .oauth.views import oauth_blueprint
from .pages.views import pages_blueprint

app.register_blueprint(users_blueprint, url_prefix='/users')
app.register_blueprint(oauth_blueprint, url_prefix='/oauth')
app.register_blueprint(pages_blueprint)

from .users.models import User

login_manager.login_view = "users.login"
login_manager.login_message = "Please login to view that page."
login_manager.login_message_category = "error"


@login_manager.user_loader
def load_user(user_id):
    """Load the logged in user for the LoginManager."""
    return User.query.filter(User.id == int(user_id)).first()


@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])


if __name__ == "__main__":
    app.run()
