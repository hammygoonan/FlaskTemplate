#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/forms.py: User forms."""

from datetime import datetime

from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.fields import HiddenField
from wtforms.fields import StringField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask import url_for
from flask_login import current_user

from project.users.models import User, ResetPassword
from project import bcrypt


class RegistationForm(FlaskForm):

    """User regisation form."""

    name = StringField(
        'Name',
        validators=[
            DataRequired(
                message="Please provide a name."
            )
        ]
    )
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
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(
                message="Please confirm your password."
            ),
            EqualTo(
                fieldname="password",
                message="Your passwords do not match."
            )
        ]
    )

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        # Standard Validation
        rv = FlaskForm.validate(self)
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


class LoginForm(FlaskForm):

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
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        # Standard Validation
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        # user validation
        user = User.query.filter_by(email=self.email.data).first()
        if user is None:
            self.email.errors.append('Your login details are incorrect.')
            return False

        # account validation
        if user.token is not None:
            self.email.errors.append('Please confirm your account before '
                                     'loggin in.')
            resend_url = url_for('.resend_confirmation') + '?email=' +\
                self.email.data
            self.email.errors.append(
                'If you do not revieve your confirmation email you can resend '
                'it by clicking <a href="' + resend_url + '">here</a>')
            return False

        # password validation
        if not bcrypt.check_password_hash(
            user.password, self.password.data
        ):
            self.password.errors.append('Your login details are incorrect.')
            return False

        self.user = user
        return True


class EditDetailsForm(FlaskForm):

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
    name = StringField(
        'Name',
        validators=[
            DataRequired(
                message="Please provide a name."
            )
        ]
    )

    def __init__(self, *args, **kwargs):
        """Initialise."""
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        """Non standard validation methods."""
        # Standard Validation
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        # user validation
        user = User.query.filter_by(email=self.email.data).first()
        if user and user != current_user:
            self.email.errors.append(
                'There is already an account with this email address.'
            )
            return False

        self.user = user
        return True


class EditPasswordForm(FlaskForm):

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
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(
                message="Please confirm your password."
            ),
            EqualTo(
                fieldname="password",
                message="Your passwords do not match."
            )
        ]
    )


class ForgotPasswordForm(FlaskForm):

    """Forgot Password form."""

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

    def validate(self):
        """Non standard validation methods."""
        # Standard Validation
        rv = FlaskForm.validate(self)
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


class ResetPasswordForm(FlaskForm):
    code = HiddenField('Code', validators=[DataRequired(
        message="Something is wrong. Please try again and contact the" +
                " administrator if your issue persists."
    )])
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
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(
                message="Please confirm your password."
            ),
            EqualTo(
                fieldname="password",
                message="Your passwords do not match."
            )
        ]
    )

    def validate(self):
        # Standard Validation
        rv = FlaskForm.validate(self)
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
