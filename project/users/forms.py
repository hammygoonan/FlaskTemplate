#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/forms.py: User forms."""

from flask_wtf import Form
from wtforms import PasswordField
from flask_wtf.html5 import EmailField
from wtforms.validators import DataRequired, Length, Email

from project.models import User
from project import bcrypt


class RegistationForm(Form):

    """User regisation form."""

    email = EmailField(
        'Email',
        validators=[
            DataRequired(
                message="Please provide an email address."
            ),
            Email(
                message="Please provide a valid email address."
            )
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(
                message="Please provide a password."
            ),
            Length(
                min=8,
                message="Password must be at least eight characters long."
            )
        ]
    )

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        # Standard Validation
        rv = Form.validate(self)
        if not rv:
            return False

        # user validation
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append(
                'There is already an account with this email address.'
            )
            return False

        self.user = user
        return True


class LoginForm(Form):

    """User login form."""

    email = EmailField(
        'Email',
        validators=[
            DataRequired(
                message="Please provide an email address."
            ),
            Email(
                message="Please provide a valid email address."
            )
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(
                message="Please provide a password."
            )
        ]
    )

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        # Standard Validation
        rv = Form.validate(self)
        if not rv:
            return False

        # user validation
        user = User.query.filter_by(email=self.email.data).first()
        if user is None:
            self.email.errors.append('Your login details are incorrect.')
            return False

        # password validation
        if not bcrypt.check_password_hash(
            user.password, self.password.data
        ):
            self.password.errors.append('Your login details are incorrect.')
            return False

        self.user = user
        return True


class EditForm(Form):

    """User edit form."""

    email = EmailField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])


class ResetPassword(Form):
    pass
