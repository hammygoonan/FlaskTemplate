#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/views.py: User views."""

from datetime import datetime, timedelta
from flask import render_template, Blueprint, request, flash, redirect,\
    url_for, session
from flask.ext.login import login_user, login_required, logout_user,\
    current_user

from project import app, db, bcrypt, random_str
from project.models import User, ResetPassword
from project.emailer.emailer import Emailer
from .forms import RegistationForm
from .forms import LoginForm
from .forms import EditPasswordForm
from .forms import EditEmailForm
from .forms import ForgotPasswordForm
from .forms import ResetPasswordForm

users_blueprint = Blueprint(
    'users', __name__,
    template_folder='templates'
)


@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    """Login route."""
    form = LoginForm()
    if form.validate_on_submit():
        login_user(form.user)
        return redirect('/')

    return render_template('login.html', form=form)


@users_blueprint.route('/logout')
@login_required
def logout():
    """Logout route."""
    logout_user()
    flash('You were logged out')
    return redirect(url_for('users.login'))


@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    """Register route."""
    form = RegistationForm()

    if form.validate_on_submit():
        db.session.add(
            User(request.form['email'], request.form['password'])
        )
        db.session.commit()
        flash('Thanks for signing up. You can now login below.')
        return redirect(url_for('users.login'))

    return render_template('register.html', form=form)


@users_blueprint.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password route."""
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        code = random_str(25)
        expires = datetime.utcnow() + timedelta(hours=24)

        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        db.session.add(ResetPassword(user, code, expires))
        db.session.commit()

        reset_url = url_for('users.reset_password', path=code)
        # send email
        message = """
        <html>
            <head></head>
            <body>
                <p>Hello,</p>
                <p>Someone has requested an email reset.</p>
                <p>If that was you, please go to <a href="{}">{}</a>.</p>
                <p>If it was not you, please just ignore this email.</p>
                <p>Please note that replies to this email are unlikely to
                be read in a timely fashion, if at all.</p>
            </body>
        </html>
        """.format(reset_url, reset_url)
        email = Emailer(user.email, app.config.get('ADMIN_EMAIL'),
                        'Email reset', message)
        email.send()
        flash('Your password has been reset, please check your email.')

    return render_template('forgot_password.html', form=form)


@users_blueprint.route('/reset_password/<path:path>', methods=['GET', 'POST'])
def reset_password(path):
    """Reset password route."""
    reset = ResetPassword.query.filter_by(code=path).first_or_404()
    if datetime.utcnow() > reset.expires:
        error = 'That reset token has expired.'
        session['form_errors'] = {'error': [error]}
        return redirect(url_for('users.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        reset.user.password = bcrypt.generate_password_hash(
            request.form.get('password')
        )
        db.session.add(reset.user)
        db.session.delete(reset)
        db.session.commit()
        flash('Your password has been updated. Please login below.')
        return redirect(url_for('users.login'))

    return render_template(
        'reset_password.html',
        form=form,
        code=reset.code
    )


@users_blueprint.route('/edit', methods=['GET'])
@login_required
def edit():
    email_form = EditEmailForm()
    password_form = EditPasswordForm()
    return render_template(
        'edit.html',
        email_form=email_form,
        password_form=password_form
    )


@users_blueprint.route('/edit/email', methods=['POST'])
@login_required
def edit_email():
    """Edit user route."""
    form = EditEmailForm()

    if request.form['email'] == current_user.email:
        flash('No changes have been made to your email address.')
        return redirect(url_for('users.edit'))

    if form.validate_on_submit():
        current_user.email = request.form['email']
        db.session.commit()
        session.pop('form_errors', None)
        flash('Your email address has been updated.')

    else:
        session['form_errors'] = form.errors

    return redirect(url_for('users.edit'))


@users_blueprint.route('/edit/password', methods=['POST'])
@login_required
def edit_password():
    """Edit user route."""
    form = EditPasswordForm()

    if form.validate_on_submit():
        current_user.password = bcrypt.generate_password_hash(
            request.form['password']
        )
        db.session.commit()
        session.pop('form_errors', None)
        flash('Your password has been updated.')
    else:
        session['form_errors'] = form.errors
    return redirect(url_for('users.edit'))
