#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""models.py: Website data models."""

from project import db
from project import bcrypt


class User(db.Model):

    """User model."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    token = db.Column(db.String)

    def __init__(self, email, password, token):
        """Initialise model."""
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.token = token

    def is_authenticated(self):
        """User validated if account has been confirmed."""
        if self.token is None:
            return True
        return False

    def is_active(self):
        """All users are automatically active."""
        return True

    def is_anonymous(self):
        """No anonymous users."""
        return False

    def get_id(self):
        """Make sure id returned is unicode."""
        return self.id

    def __repr__(self):
        """Representation."""
        return '<user {}>'.format(self.email)


class ResetPassword(db.Model):

    """Reset Password model."""

    __tablename__ = "reset"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    code = db.Column(db.String)
    expires = db.Column(db.DateTime)

    user = db.relationship('User')

    def __init__(self, user, code, expires):
        """Initialise model."""
        self.user = user
        self.code = code
        self.expires = expires

    def __repr__(self):
        """Representation."""
        return '<user {}>'.format(self.code)
