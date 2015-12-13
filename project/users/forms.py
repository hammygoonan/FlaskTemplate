#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/forms.py: User forms."""

from flask_wtf import Form
from wtforms import PasswordField
from flask_wtf.html5 import EmailField
from wtforms.validators import DataRequired, Length, Email


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


class LoginForm(Form):

    """User login form."""

    email = EmailField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])


class EditForm(Form):

    """User edit form."""

    email = EmailField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

class ResetPassword(Form):
    pass
