#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

from tests.base import BaseTestCase
from flask.ext.login import current_user
from project import bcrypt
from project.emailer.emailer import Emailer
from project.models import User, ResetPassword
from flask import url_for
from mock import patch


class UsersTestCase(BaseTestCase):

    """User test cases."""

    def setUp(self):
        """Setup User tests."""
        self.email = 'test_1@example.com'
        self.password = 'password'

        self.new_email = 'new@example.com'
        self.new_password = 'new_password'

        self.other_email = 'test_3@example.com'
        self.other_password = 'other_password'

        self.err_email = 'error@example.com'
        self.err_password = 'abc'

        super().setUp()

    # Login page
    def test_login_page(self):
        """Test login page."""
        response = self.client.get('/users/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)
        self.assertIn(b'<title>Login', response.data)

    def test_can_login(self):
        """Test user can login."""
        with self.client:
            response = self.login()
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'FlaskTemplate', response.data)
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
            self.assertIn(b'Your login details are incorrect.', response.data)

    # Register page tests
    def test_register_page(self):
        """Test register page."""
        response = self.client.get('/users/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Register', response.data)
        self.assertIn(b'<title>Register', response.data)

    def test_user_cannt_register_without_email(self):
        """Check cannot register without email."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': '',
                    'password': self.other_password
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide an email address.',
                          response.data)

    def test_user_cannt_register_without_password(self):
        """Test password is required to register."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.new_email,
                    'password': ''
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide a password.',
                          response.data)

    def test_register_email_validation(self):
        """Test registration has valid email address."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': 'not an email address',
                    'password': 'password'
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide a valid email address.',
                          response.data)

    def test_password_at_least_eight_char(self):
        """Test password length when registering."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.new_email,
                    'password': '1234'
                },
                follow_redirects=True
            )
            self.assertIn(b'Password must be at least eight characters long.',
                          response.data)

    def test_user_can_create_account(self):
        """Test user can create an account."""
        # correct details
        response = self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn('Thanks for signing up. You can now login below.',
                      str(response.data))

    def test_email_is_unique_when_registering(self):
        """Test email is not already in use when registering."""
        self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password
            },
            follow_redirects=True
        )
        response = self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn('There is already an account with this email address',
                      str(response.data))

    # logout
    def test_logout(self):
        """Test user can logout."""
        with self.client:
            self.login()
            response = self.client.get('/users/logout', follow_redirects=True)
            self.assertIn(b'You were logged out', response.data)

    def test_logout_route_requires_login(self):
        """Ensure that logout page requires user login."""
        response = self.client.get('/users/logout', follow_redirects=True)
        self.assertIn(b'Please login to view that page.', response.data)

    # forgot password
    def test_forgot_password_page(self):
        """Test that forgot password page exists."""
        response = self.client.get('/users/forgot_password',
                                   follow_redirects=True)
        self.assert200(response)
        self.assertIn(b'Forgot Password', response.data)
        self.assertIn(b'<title>Forgot Password', response.data)

    def test_forgot_password_has_valid_email(self):
        response = self.client.post(
            '/users/forgot_password',
            data={
                'email': "Not an email",
            },
            follow_redirects=True
        )
        self.assertIn(b'Please provide a valid email address.', response.data)

    def test_forgot_password_email_in_database(self):
        response = self.client.post(
            '/users/forgot_password',
            data={
                'email': self.new_email,
            },
            follow_redirects=True
        )
        self.assertIn(
            b'We don&#39;t have an account with that email address.',
            response.data
        )

    @patch.object(Emailer, 'send')
    def test_entry_made_in_forgot_password_database(self, mock_send):
        self.client.post(
            '/users/forgot_password',
            data={
                'email': self.email,
            },
            follow_redirects=True
        )
        user = User.query.filter_by(email=self.email).first()
        entry = ResetPassword.query.filter_by(user=user)
        self.assertTrue(entry)

    @patch.object(Emailer, 'send')
    def test_flash_message_for_forgot_password(self, mock_send):
        response = self.client.post(
            '/users/forgot_password',
            data={
                'email': self.email,
            },
            follow_redirects=True
        )
        self.assertIn(
            b'Your password has been reset, please check your email.',
            response.data
        )

    # reset password

    def test_reset_password_page_exists(self):
        response = self.client.get('/users/reset_password/resetcode')
        self.assert200(response)
        self.assertIn(b'Reset Password', response.data)
        self.assertIn(b'<title>Reset Password', response.data)

    def test_password_is_required(self):
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': ''
            },
            follow_redirects=True
        )
        self.assertIn(b'Please provide a password.', response.data)

    def test_reset_password_page_requires_token(self):
        response = self.client.get('/users/reset_password/')
        self.assert404(response)

    def test_reset_password_page_email_must_exist(self):
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.new_email,
                'password': self.password,
                'code': 'resetcode'
            },
            follow_redirects=True
        )
        self.assertIn(
            b'We don&#39;t have that email address in our system.',
            response.data
        )

    def test_reset_password_is_long_enough(self):
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': 'short'
            },
            follow_redirects=True
        )
        self.assertIn(
            b'Password must be at least eight characters long.',
            response.data
        )

    def test_reset_token_has_not_expired(self):
        response = self.client.get(
            '/users/reset_password/resetcode2',
            follow_redirects=True
        )
        self.assertIn(b'Forgot Password', response.data)
        self.assertIn(
            b'That reset token has expired.',
            response.data
        )

    def test_reset_has_been_requested(self):
        response = self.client.get(
            '/users/reset_password/incorrectcode',
            follow_redirects=True
        )
        self.assert404(response)

    def test_password_updated(self):
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'code': 'resetcode'
            },
            follow_redirects=True
        )
        self.assertIn(
            b'Your password has been updated. Please login below.',
            response.data
        )
        self.assertIn(
            b'Login',
            response.data
        )
        user = User.query.filter_by(email=self.email).first()
        self.assertTrue(bcrypt.check_password_hash(
            user.password, self.new_password
        ))

    def test_token_deleted_once_used(self):
        self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'code': 'resetcode'
            }
        )
        token = ResetPassword.query.filter_by(code="resetcode").first()
        self.assertEqual(None, token)

    def test_reset_fails_if_no_token(self):
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'code': ''
            },
            follow_redirects=True
        )
        self.assertIn(
            b"Something is wrong. Please try again and contact the" +
            b" administrator if your issue persists.",
            response.data
        )

    # Edit page
    def test_edit_page(self):
        """Test user edit page."""
        with self.client:
            self.login()
            response = self.client.get('/users/edit')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Edit your email', response.data)
            self.assertIn(b'Edit your password', response.data)
            self.assertIn(b'<title>Edit details', response.data)

    def test_user_can_change_email(self):
        """Test the user can update email."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/email',
                data={
                    'email': self.new_email,
                },
                follow_redirects=True
            )
            self.assertTrue(current_user.email == self.new_email)
            self.assertIn(
                b'Your email address has been updated.',
                response.data
            )

    def test_email_unique_when_editing(self):
        """Test that email being edited is unique and email is not updated."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/email',
                data={
                    'email': self.other_email
                },
                follow_redirects=True
            )
            # check email has not been updated
            self.assertTrue(current_user.email ==
                            self.email)
            # display flash message
            self.assertIn(
                b'There is already an account with this email address.',
                response.data
            )

    def test_user_email_valid_when_editing(self):
        """Test users email is valid when editing it."""
        with self.client:
            self.login()
            # no email address
            response = self.client.post(
                '/users/edit/email',
                data={
                    'email': 'Invalidemailaddress'
                },
                follow_redirects=True
            )
            # display flash message
            self.assertIn(b'Please provide a valid email address.',
                          response.data)

    def test_new_email_is_different(self):
        """Test edited email is unique."""
        with self.client:
            self.login()
            # no email address
            response = self.client.post(
                '/users/edit/email',
                data={
                    'email': self.email
                },
                follow_redirects=True
            )
            # display flash message
            self.assertIn(b'No changes have been made to your email address.',
                          response.data)

    def test_user_can_change_password(self):
        """Test the user can update email."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/password',
                data={
                    'password': self.new_password,
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Your password has been updated.',
                response.data
            )
            self.assertTrue(bcrypt.check_password_hash(
                current_user.password, self.new_password
            ))

    def test_cannt_change_password_if_less_than_eight_char(self):
        """Test password length when editing."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/password',
                data={
                    'password': '1234',
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Password must be at least eight characters long.',
                response.data
            )

    # helper methods
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
