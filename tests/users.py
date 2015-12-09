#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

from tests.base import BaseTestCase
from flask.ext.login import current_user
from project import bcrypt
from project.emailer.emailer import Emailer
from project.models import User, ResetPassword, Invitation
from flask import url_for
from mock import patch


class UsersTestCase(BaseTestCase):

    """User test cases."""

    def setUp(self):
        """Setup User tests."""
        self.email = 'test_1@example.com'
        self.password = 'password'

        self.new_email = 'test_2@example.com'
        self.new_password = 'new_password'

        self.other_email = 'test_3@example.com'
        self.other_password = 'other_password'

        self.invite_email = 'test_4@example.com'
        self.invite_code = 'invite_code'
        self.invite_password = 'invite_password'

        self.err_email = 'error@example.com'
        self.err_password = 'abc'

        super().setUp()

    def test_login_page(self):
        """Test login page."""
        response = self.client.get('/users/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)

    def test_can_login(self):
        """Test user can login."""
        with self.client:
            response = self.login()
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Link', response.data)
            self.assertTrue(current_user.is_active())
            self.assertTrue(current_user.email == self.email)

    def test_cant_login(self):
        """Test that can't login with incorrect details and flash message."""
        with self.client:
            response = self.client.post(
                '/users/login',
                follow_redirects=True,
                data=dict(
                    email=self.err_email,
                    password=self.err_password
                ),
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Invalid username or password.', response.data)
            self.assertFalse(current_user.is_active())

    def test_register_page(self):
        """Test register page."""
        response = self.client.get('/users/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Register', response.data)

    @patch.object(Emailer, 'send')
    def test_forgot_password_page(self, mock_send):
        """Test forgot password page with mocked Emailer."""
        response = self.client.get('/users/forgot_password')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Forgot Password', response.data)
        with self.client:
            response = self.client.post(
                '/users/forgot_password',
                data={
                    'email': self.email,
                },
                follow_redirects=True
            )
            self.assertIn('Your password has been reset, please check your ' +
                          'email.', str(response.data))
            user = User.query.filter_by(email=self.email)\
                .first()
            self.assertTrue(
                ResetPassword.query.filter_by(user_id=user.id)
            )
        with self.client:
            response = self.client.post(
                '/users/forgot_password',
                data={
                    'email': self.err_email,
                },
                follow_redirects=True
            )
            self.assertIn('Sorry, we don&#39;t have that email address in ' +
                          'our system.', str(response.data))

    def test_reset_password_page(self):
        """Test reset password."""
        # should be a 404 if code is not recognised
        response = self.client.get('/users/reset_password/thisisacode')
        self.assert404(response)
        # check user_id is set
        with self.client:
            response = self.client.get('/users/reset_password/resetcode')
            self.assertIn(b'<input type="hidden" name="user_id" value="1" />',
                          response.data)
        # should not update if no password provided
        with self.client:
            response = self.client.post(
                '/users/reset_password/resetcode',
                data={
                    'password': '',
                },
                follow_redirects=True
            )
            self.assert200(response)
            self.assertTrue(b'Sorry, something&#39;s not right here. Did ' +
                            b'you enter and email address?.', response.data)

        # should update password if code is recongnised
        with self.client:
            response = self.client.post(
                '/users/reset_password/resetcode',
                data={
                    'password': self.new_password,
                    'user_id': 1
                },
                follow_redirects=True
            )
            self.assert200(response)
            self.assertTrue(b'Your password has been reset, please login ' +
                            b'below', response.data)
            # check password has changed
            user = User.query.filter_by(email=self.email)\
                .first()
            self.assertTrue(
                bcrypt.check_password_hash(
                    user.password, self.new_password
                )
            )
        # check it breaks if link has expired.
        with self.client:
            response = self.client.get(
                '/users/reset_password/resetcode2',
                follow_redirects=True
            )
            self.assert200(response)
            self.assertTrue(b'That link has expired. Please reset your ' +
                            b'password again.', response.data)

    def test_edit_page(self):
        """Test user edit page."""
        with self.client:
            self.login()
            response = self.client.get('/users/edit')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Edit your details', response.data)

    def test_logout(self):
        """Test user can logout."""
        with self.client:
            self.login()
            response = self.client.get('/users/logout', follow_redirects=True)
            self.assertIn(b'You were logged out', response.data)
            self.assertFalse(current_user.is_active())

    def test_logout_route_requires_login(self):
        """Ensure that logout page requires user login."""
        response = self.client.get('/users/logout', follow_redirects=True)
        self.assertIn(b'Please login to view that page.', response.data)

    def test_user_can_change_email(self):
        """Test the user can update email."""
        with self.client:
            response = self.client.post(
                '/users/login',
                data={
                    'email': self.email,
                    'password': self.password
                },
                follow_redirects=True
            )
            self.assertTrue(current_user.email == self.email)
            # update email
            response = self.client.post(
                '/users/edit',
                data={
                    'email': self.new_email,
                    'password': ''
                },
                follow_redirects=True
            )
            # check email has been updated
            self.assertTrue(current_user.email ==
                            self.new_email)
            # make sure password hasn't been updated
            password = bcrypt.check_password_hash(
                current_user.password, self.password
            )
            self.assertTrue(password)
            # check flash message
            self.assertIn(b'Your details have been updated', response.data)

    def test_user_can_change_password(self):
        """Test that user can change password."""
        with self.client:
            self.login()
            user_password = bcrypt.check_password_hash(
                current_user.password, self.password
            )
            self.assertTrue(user_password)
            response = self.client.post(
                '/users/edit',
                data={
                    'email': self.email,
                    'password': self.new_password
                },
                follow_redirects=True
            )
            # check password is updated
            new_password = bcrypt.check_password_hash(
                current_user.password, 'new_password'
            )
            self.assertTrue(new_password)
            # check email remains the same
            self.assertTrue(current_user.email ==
                            self.email)
            # check flash message
            self.assertIn(b'Your details have been updated', response.data)

    def test_user_unique_when_editing(self):
        """Test that email being edited is unique and email is not updated."""
        with self.client:
            self.login()
            self.assertTrue(current_user.email == self.email)
            response = self.client.post(
                '/users/edit',
                data={
                    'email': self.other_email,
                    'password': ''
                },
                follow_redirects=True
            )
            # check email has not been updated
            self.assertTrue(current_user.email ==
                            self.email)
            # display flash message
            self.assertIn(b'That email address is already in use.',
                          response.data)

    def test_user_email_valid_when_editing(self):
        with self.client:
            self.login()
            # no email address
            response = self.client.post(
                '/users/edit',
                data={
                    'email': '',
                    'password': ''
                },
                follow_redirects=True
            )
            # display flash message
            self.assertIn(b'Please enter a valid email address.',
                          response.data)
            # invalid email address
            response = self.client.post(
                '/users/edit',
                data={
                    'email': 'not an email',
                    'password': ''
                },
                follow_redirects=True
            )
            # display flash message
            self.assertIn(b'Please enter a valid email address.',
                          response.data)
            # change email but not password
            response = self.client.post(
                '/users/edit',
                data={
                    'email': '',
                    'password': 'new password'
                },
                follow_redirects=True
            )
            # display flash message
            self.assertIn(b'Please enter a valid email address.',
                          response.data)

    def test_user_cannt_register_without_all_fields(self):
        """Check all fields are required for user registration."""
        with self.client:
            # check invite required
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.invite_email,
                    'password': self.other_password,
                    'invite': ''
                },
                follow_redirects=True
            )
            self.assertIn(b'Please ensure you fill in all fields.',
                          response.data)
            # check password required
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.invite_email,
                    'password': '',
                    'invite': self.invite_code
                },
                follow_redirects=True
            )
            self.assertIn(b'Please ensure you fill in all fields.',
                          response.data)
            # check email required
            response = self.client.post(
                '/users/register',
                data={
                    'email': '',
                    'password': self.invite_password,
                    'invite': self.invite_code
                },
                follow_redirects=True
            )
            self.assertIn(b'Please ensure you fill in all fields.',
                          response.data)

    def test_user_can_create_account(self):
        """Test user can create an account."""
        # wrong code
        response = self.client.post(
            '/users/register',
            data={
                'email': self.err_email,
                'password': self.invite_password,
                'invite': self.invite_code
            },
            follow_redirects=True
        )
        self.assertIn('Sorry, we don&#39;t have a invite that matches that '
                      'email address and invitation code.', str(response.data))
        # email wrong
        response = self.client.post(
            '/users/register',
            data={
                'email': self.err_email,
                'password': self.password,
                'invite': self.invite_code
            },
            follow_redirects=True
        )
        self.assertIn('Sorry, we don&#39;t have a invite that matches that '
                      'email address and invitation code.', str(response.data))
        # correct details
        response = self.client.post(
            '/users/register',
            data={
                'email': self.invite_email,
                'password': self.invite_password,
                'invite': self.invite_code
            },
            follow_redirects=True
        )
        self.assertIn('Thanks for signing up! Please login below.',
                      str(response.data))

    def test_invite_page(self):
        """Test invite page."""
        with self.client:
            self.login()
            response = self.client.get(
                url_for('users.invitation')
            )
            self.assertIn(b'Invite someone to join', response.data)

    def test_valid_email_for_invitation(self):
        """Test invitations can't be sent to dodgy emails addresses."""
        with self.client:
            self.login()
            response = self.client.post(
                url_for('users.invitation'),
                data={'email': 'Not an email address'},
                follow_redirects=True
            )
            self.assertIn(
                'That email doesn&#39;t look like an email address...',
                str(response.data))

    @patch.object(Emailer, 'send')
    def test_can_add_invition(self, mock_send):
        """Test user can invite someone."""
        with self.client:
            self.login()
            response = self.client.post(
                url_for('users.invitation'),
                data={'email': 'general@email.com'},
                follow_redirects=True
            )
            self.assertIn(
                b'general@email.com has been sent an invitation.',
                response.data)
            self.assertTrue(
                Invitation.query.filter_by(email=self.invite_email).first())

    def test_cant_add_invition_if_already_invited(self):
        """Test someone can't be invited more than once."""
        with self.client:
            self.login()
            response = self.client.post(
                url_for('users.invitation'),
                data={'email': self.invite_email},
                follow_redirects=True
            )
            self.assertIn(
                '{} has already been sent an invitation.'.format(
                    self.invite_email),
                str(response.data))

            # current user
            response = self.client.post(
                url_for('users.invitation'),
                data={'email': self.other_email},
                follow_redirects=True
            )
            self.assertIn(
                '{} has already been sent an invitation.'.format(
                    self.other_email),
                str(response.data))
            self.assertTrue(
                Invitation.query.filter_by(email=self.invite_email).first())

    def login(self):
        """Login to site."""
        return self.client.post(
            url_for('users.login'),
            follow_redirects=True,
            data={
                'email': self.email,
                'password': self.password
            },
        )
