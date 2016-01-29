#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""users/views.py: User views."""

from datetime import datetime, timedelta

from flask import render_template, Blueprint, request, flash, redirect,\
    url_for, session, abort
from flask.ext.login import login_user, login_required, logout_user,\
    current_user

from project import app, db, bcrypt, random_str
from project.users.models import User, ResetPassword
from project.mail.mail import send_forgot_password, send_registration
from .forms import RegistationForm
from .forms import LoginForm
from .forms import EditPasswordForm
from .forms import EditDetailsForm
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
        next_page = None
        if 'next_page' in session:
            next_page = session['next_page']
            session.pop('next_page', None)
        return redirect(next_page or url_for('pages.home'))

    if request.args.get('next'):
        session['next_page'] = request.args.get('next')
    return render_template('login.html', form=form)


@users_blueprint.route('/modal_login')
def modal_login():
    """Login route."""
    form = LoginForm()
    if request.args.get('next'):
        session['next_page'] = request.args.get('next')
    return render_template('modal_login.html', form=form)


@users_blueprint.route('/logout')
@login_required
def logout():
    """Logout route."""
    logout_user()
    if 'oauth_token' in session:
        session.pop('oauth_token', None)
    flash('You were logged out', 'info')
    return redirect(url_for('users.login'))


@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    """Register route."""
    form = RegistationForm()
    if form.validate_on_submit():
        token = random_str(30)
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        db.session.add(User(name, email, password, token))
        db.session.commit()

        reset_url = url_for('users.confirm_account', token=token,
                            _external=True)
        send_registration(
            {
                'to': email,
                'subject': 'Project confirmation email'
            },
            values=[
                name, reset_url, reset_url
            ]
        )

        flash('Thanks for signing up. Please check your email to for a'
              ' confirmation link so we know you\'re human.', 'info')
        resend_url = url_for('.resend_confirmation') + '?email=' + email
        flash('If you do not revieve your confirmation email you can resend '
              'it by clicking <a href="' + resend_url + '">here</a>', 'info')
        return redirect(url_for('users.login'))

    return render_template('register.html', form=form)


@users_blueprint.route('/resend_confirmation')
def resend_confirmation():
    email = request.args.get('email', None)
    if email is None:
        abort(404)

    user = User.query.filter_by(email=email).first()
    reset_url = url_for('users.confirm_account', token=user.token,
                        _external=True)
    send_registration(
        {
            'to': email,
            'subject': 'Project confirmation email'
        },
        values=[
            user.name, reset_url, reset_url
        ]
    )
    flash('Your email confirmation has been resent. Please check your inbox.',
          'info')
    return redirect(url_for('users.login'))


@users_blueprint.route('/confirm_account/<token>')
def confirm_account(token):
    """Confirm password page."""
    user = User.query.filter_by(token=token).first_or_404()
    user.token = None
    db.session.commit()
    flash('Thanks for confirming your email address. You\'re good to go. '
          'Please login below.', 'info')
    return redirect(url_for('users.login'))


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

        reset_url = url_for('users.reset_password', path=code, _external=True)

        # send email
        send_forgot_password(
            {
                'to': user.email,
                'subject': 'Project reset password'
            },
            values=[
                reset_url, reset_url
            ]
        )
        flash('A password reset link has been emailed to you, please check '
              'your email.', 'info')
        return redirect(url_for('users.login'))

    return render_template('forgot_password.html', form=form)


@users_blueprint.route('/reset_password/<path:path>', methods=['GET', 'POST'])
def reset_password(path):
    """Reset password route."""
    reset = ResetPassword.query.filter_by(code=path).first_or_404()
    if datetime.utcnow() > reset.expires:
        flash('That reset token has expired.', 'error')
        return redirect(url_for('users.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        reset.user.password = bcrypt.generate_password_hash(
            request.form.get('password')
        )
        db.session.add(reset.user)
        db.session.delete(reset)
        db.session.commit()
        flash('Your password has been updated. Please login below.', 'info')
        return redirect(url_for('users.login'))

    return render_template(
        'reset_password.html',
        form=form,
        code=reset.code
    )


@users_blueprint.route('/edit', methods=['GET'])
@login_required
def edit():
    """Edit route."""
    form = EditDetailsForm()
    password_form = EditPasswordForm()
    return render_template(
        'edit.html',
        form=form,
        password_form=password_form
    )


@users_blueprint.route('/edit/details', methods=['POST'])
@login_required
def edit_details():
    """Edit user route."""
    form = EditDetailsForm()

    if form.validate_on_submit():
        current_user.email = request.form['email']
        current_user.name = request.form['name']
        db.session.commit()
        flash('Your details have been updated.', 'info')

    else:
        for errors, messages in form.errors.items():
            for message in messages:
                flash(message, 'error')

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
        flash('Your password has been updated.', 'info')
    else:
        for errors, messages in form.errors.items():
            for message in messages:
                flash(message, 'error')
    return redirect(url_for('users.edit'))


@users_blueprint.route('/delete', methods=['POST'])
@login_required
def delete():
    """Edit route."""
    user = current_user
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Your account as been deleted. Yikes!', 'info')
    return redirect(url_for('users.login'))
