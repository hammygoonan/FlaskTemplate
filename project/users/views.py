#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/views.py: User views."""

from datetime import datetime, timedelta
from flask import render_template, Blueprint, request, flash, redirect,\
    url_for
from flask.ext.login import login_user, login_required, logout_user,\
    current_user

from project import app, db, bcrypt, random_str
from project.models import User, ResetPassword
from project.emailer.emailer import Emailer
from .forms import RegistationForm

users_blueprint = Blueprint(
    'users', __name__,
    template_folder='templates'
)


@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    """Login route."""
    if request.method == "POST":
        user = User.query.filter_by(email=request.form['email']).first()
        if user is not None and bcrypt.check_password_hash(
            user.password, request.form['password']
        ):
            login_user(user)
            return redirect('/')

        else:
            flash('Invalid username or password.')

    return render_template('login.html')


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
    if request.method == "POST":
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Sorry, we don\'t have that email address in our system.')
            return render_template('forgot_password.html')
        else:
            code = random_str(25)
            expires = datetime.utcnow() + timedelta(hours=24)
            db.session.add(ResetPassword(user, code, expires))
            db.session.commit()
            reset_url = '{}users/reset_password/{}'.format(
                app.config['DOMAIN_NAME'],
                code
            )
            # send email
            message = """\
            <html>
                <head></head>
                <body>
                    <p>Hello,</p>
                    <p>Someone has requested an email reset.</p>
                    <p>If that was you, please go to <a href="{}">{}</a>.</p>
                    <p>If it was not you, please just ignore this email.</p>
                    <p>Please note that replies to this email are unlikely to
                    be read in a timely fashion if at all.</p>
                </body>
            </html>
            """.format(reset_url, reset_url)
            email = Emailer(user.email, app.config.get('ADMIN_EMAIL'),
                            'Email reset', message)
            email.send()
            flash('Your password has been reset, please check your email.')

    return render_template('forgot_password.html')


@users_blueprint.route('/reset_password/<path:path>', methods=['GET', 'POST'])
def reset_password(path):
    """Reset password route."""
    if request.method == "POST":
        password = request.form.get('password')
        user = request.form.get('user_id')
        if password and user:
            user = User.query.get(user)
            user.password = bcrypt.generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated. Please login below.')
            return redirect(url_for('users.login'))
        else:
            flash('Sorry, something\'s not right here. Did you enter and '
                  'email address?.')

    reset = ResetPassword.query.filter_by(code=path).first_or_404()
    # moke sure link not expired
    if reset.expires < datetime.utcnow():
        flash('That link has expired. Please reset your password again.')
        return redirect(url_for('users.forgot_password'))
    return render_template('reset_password.html', user=reset.user_id)


@users_blueprint.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    """Edit user route."""
    if request.method == "POST":
        email = request.form.get('email')
        if not email or not is_email(email):
            flash('Please enter a valid email address.')
            return render_template('edit.html', user=current_user)
        user = User.query.filter_by(email=email).first()
        # if email is already taken
        if user and user.id != current_user.id:
            flash('That email address is already in use.')
        else:
            user = User.query.get(current_user.id)
            # update password if changed
            if request.form['password'] != '':
                user.password = bcrypt.generate_password_hash(
                    request.form['password']
                )
            # update email if changed
            if current_user.email != request.form['email']:
                user.email = request.form['email']
            db.session.commit()
            flash('Your details have been updated')
    return render_template('edit.html', user=current_user)


@users_blueprint.route('/invitation', methods=['GET', 'POST'])
@login_required
def invitation():
    """Invitation route."""
    if request.method == "POST":
        email = request.form.get('email')
        if not is_email(email):
            flash('That email doesn\'t look like an email address...')
            return render_template('invitation.html')
        if not email:
            flash('Aren\'t you forgetting something?')
            return render_template('invitation.html')
        invite = Invitation.query.filter_by(email=email).first()
        current_user = User.query.filter_by(email=email).first()
        if invite or current_user:
            flash('{} has already been sent an invitation.'.format(email))
            return render_template('invitation.html')
        code = random_str()
        db.session.add(Invitation(email, code))
        db.session.commit()
        invite_url = '{}users/register'.format(
            app.config.get('DOMAIN_NAME'))
        flash('{} has been sent an invitation.'.format(email))

        # send email
        message = """\
        <html>
            <head></head>
            <body>
                <p>Hello,</p>
                <p>Someone has been kind enough to send you an
                invitation to {}.</p>
                <p>To activate your account go to:
                <a href="{}">{}</a>. and end the code '{}'</p>
                <p>Please note that replies to this email are unlikely
                to be read in a timely fashion if at all.</p>
            </body>
        </html>
        """.format(app.config.get('DOMAIN_NAME'),
                   invite_url, invite_url, code)
        email = Emailer(
            email,
            app.config.get('ADMIN_EMAIL'),
            '{} invitation'.format(app.config.get('DOMAIN_NAME')),
            message
        )
        email.send()
    return render_template('invitation.html')
