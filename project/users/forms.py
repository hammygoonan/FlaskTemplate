#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/forms.py: User forms."""

from datetime import datetime

from flask_wtf import Form
from wtforms import PasswordField
from flask_wtf.html5 import EmailField
from wtforms.fields import HiddenField
from wtforms.validators import DataRequired, Length, Email
from flask import url_for

from project.models import User, ResetPassword
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


class EditEmailForm(Form):

    """User edit form."""

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


class EditPasswordForm(Form):

    """User edit form."""

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


class ForgotPasswordForm(EditEmailForm):
    def validate(self):
        # Standard Validation
        rv = Form.validate(self)
        if not rv:
            return False

        # user validation
        user = User.query.filter_by(email=self.email.data).first()
        if not user:
            self.email.errors.append(
                'We don\'t have an account with that email address.'
            )
            return False

        self.user = user
        return True


class ResetPasswordForm(RegistationForm):
    code = HiddenField('Code', validators=[DataRequired(
        message="Something is wrong. Please try again and contact the" +
                " administrator if your issue persists."
    )])

    def validate(self):
        # Standard Validation
        rv = Form.validate(self)
        if not rv:
            return False

        # user validation
        user = User.query.filter_by(email=self.email.data).first()
        if user is None:
            self.code.errors.append(
                'We don\'t have that email address in our system.'
            )
            return False

        forgot = ResetPassword.query.filter_by(
            user=user,
            code=self.code.data
        ).first()
        if forgot is None:
            self.forgot.errors.append(
                'There has been no request to reset your password.'
            )
            return False

        if datetime.utcnow() > forgot.expires:
            self.forgot.errors.append(
                'That reset token has expired. <a href="{}">Click here</a>'
                ' to send a new reset link.'.format(
                    url_for('users.forgot_password')
                )
            )
            return False

        self.user = user
        return True
