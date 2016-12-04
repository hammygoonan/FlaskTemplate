#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Main app entry point."""

import random
import string
import re
import os

from flask import Flask
from flask import send_from_directory
from flask import request
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from .flask_mailgun.flask_mailgun import Mailgun
from .errors import ErrorHandler


db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
mailgun = Mailgun()


def create_app(config=None):
    """Create application.
    :param string: object name to inialise application
    :return `Class`: Flask object
    """
    app = Flask(__name__)
    if config:
        app.config.from_object(config)
    else:
        app.config.from_object(os.environ['PROJECT_SETTINGS'])

    db.app = app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mailgun.init_app(app)

    if not app.debug:
        ErrorHandler(app)

    load_blueprints(app)
    return app


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


def load_blueprints(app):
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

# 
# @current_app.route('/robots.txt')
# def static_from_root():
#     return send_from_directory(current_app.static_folder, request.path[1:])
