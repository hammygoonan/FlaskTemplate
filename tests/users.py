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
    @patch.object(Emailer, 'send')
    def test_register_page(self, mock_send):
        """Test register page."""
        response = self.client.get('/users/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Register', response.data)
        self.assertIn(b'<title>Register', response.data)

    @patch.object(Emailer, 'send')
    def test_user_cannt_register_without_email(self, mock_send):
        """Check cannot register without email."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': '',
                    'password': self.other_password,
                    'confirm_password': self.other_password
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide an email address.',
                          response.data)

    @patch.object(Emailer, 'send')
    def test_user_cannt_register_without_password(self, mock_send):
        """Test password is required to register."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.new_email,
                    'password': '',
                    'confirm_password': ''
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide a password.',
                          response.data)

    @patch.object(Emailer, 'send')
    def test_register_password_confirmation(self, mock_send):
        """Test password confirm."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.new_email,
                    'password': self.other_password,
                    'confirm_password': 'different'
                },
                follow_redirects=True
            )
            self.assertIn(b'Your passwords do not match.',
                          response.data)

    @patch.object(Emailer, 'send')
    def test_register_confirm_password_required(self, mock_send):
        """Test confirm password required on password reset."""
        response = self.client.post(
            '/users/register',
            data={
                'email': self.email,
                'password': self.new_password,
                'confirm_password': '',
                'code': 'resetcode'
            },
            follow_redirects=True
        )
        self.assertIn(
            b"Please confirm your password.",
            response.data
        )

    @patch.object(Emailer, 'send')
    def test_register_email_validation(self, mock_send):
        """Test registration has valid email address."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': 'not an email address',
                    'password': 'password',
                    'confirm_password': 'password'
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide a valid email address.',
                          response.data)

    @patch.object(Emailer, 'send')
    def test_password_at_least_eight_char(self, mock_send):
        """Test password length when registering."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'email': self.new_email,
                    'password': '1234',
                    'confirm_password': '1234'
                },
                follow_redirects=True
            )
            self.assertIn(b'Password must be at least eight characters long.',
                          response.data)

    @patch.object(Emailer, 'send')
    def test_user_can_create_account(self, mock_send):
        """Test user can create an account."""
        # correct details
        response = self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn('Please check your email to for a confirmation link',
                      str(response.data))

    @patch.object(Emailer, 'send')
    def test_new_account_in_database(self, mock_send):
        """Test new account in database with encrypted password."""
        self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        user = User.query.filter_by(email=self.new_email).first()
        self.assertTrue(user)
        self.assertTrue(bcrypt.check_password_hash(
            user.password, self.new_password
        ))

    @patch.object(Emailer, 'send')
    def test_email_is_unique_when_registering(self, mock_send):
        """Test email is not already in use when registering."""
        self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        response = self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn('There is already an account with this email address',
                      str(response.data))

    # confirm email
    @patch.object(Emailer, 'send')
    def test_email_confirmation(self, mock_send):
        """Test email confirmation."""
        self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            }
        )
        users = User.query.filter_by(email=self.new_email).first()
        self.assertTrue(users.token)
        response = self.client.get(
            '/users/confirm_account/' + users.token,
            follow_redirects=True
        )
        users = User.query.filter_by(email=self.new_email).first()
        self.assertIn('Thanks for confirming your email address.',
                      str(response.data))
        self.assertEqual(None, users.token)

    @patch.object(Emailer, 'send')
    def test_connot_login_without_confirmation(self, mock_send):
        """Test account must be confirmed to login."""
        self.client.post(
            '/users/register',
            data={
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            }
        )
        response = self.client.post(
            '/users/login',
            data={
                'email': self.new_email,
                'password': self.new_password
            }
        )
        self.assertIn("Please check your email to for a confirmation link",
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
        """Test email is valid when using forgot password."""
        response = self.client.post(
            '/users/forgot_password',
            data={
                'email': "Not an email",
            },
            follow_redirects=True
        )
        self.assertIn(b'Please provide a valid email address.', response.data)

    def test_forgot_password_email_in_database(self):
        """Test database is updated when forgot password is used."""
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
        """Test database to make sure forgot password token created."""
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
        """Test emai reset page."""
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
        """Confirm password reset page exists."""
        response = self.client.get('/users/reset_password/resetcode')
        self.assert200(response)
        self.assertIn(b'Reset Password', response.data)
        self.assertIn(b'<title>Reset Password', response.data)

    def test_password_is_required(self):
        """Test password field is required."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': '',
                'confirm_password': ''
            },
            follow_redirects=True
        )
        self.assertIn(b'Please provide a password.', response.data)

    def test_reset_password_page_requires_token(self):
        """Test reset password token is required."""
        response = self.client.get('/users/reset_password/')
        self.assert404(response)

    def test_reset_password_page_email_must_exist(self):
        """Test email on system for reset password."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.new_email,
                'password': self.password,
                'confirm_password': self.password,
                'code': 'resetcode'
            },
            follow_redirects=True
        )
        self.assertIn(
            b'We don&#39;t have that email address in our system.',
            response.data
        )

    def test_reset_password_is_long_enough(self):
        """Test password at least 8 chars."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': 'short',
                'confirm_password': 'short'
            },
            follow_redirects=True
        )
        self.assertIn(
            b'Password must be at least eight characters long.',
            response.data
        )

    def test_reset_token_has_not_expired(self):
        """Test reset token has expired."""
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
        """Test reset password token has been requested."""
        response = self.client.get(
            '/users/reset_password/incorrectcode',
            follow_redirects=True
        )
        self.assert404(response)

    def test_password_updated(self):
        """Test password is updated on reset."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'confirm_password': self.new_password,
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
        """Test password reset deletes reset."""
        self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'confirm_password': self.new_password,
                'code': 'resetcode'
            }
        )
        token = ResetPassword.query.filter_by(code="resetcode").first()
        self.assertEqual(None, token)

    def test_reset_fails_if_no_token(self):
        """Test reset password token is required."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'confirm_password': self.new_password,
                'code': ''
            },
            follow_redirects=True
        )
        self.assertIn(
            b"Something is wrong. Please try again and contact the" +
            b" administrator if your issue persists.",
            response.data
        )

    def test_reset_confirm_password_matches(self):
        """Test confirm password matches on password reset."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'confirm_password': 'different',
                'code': 'resetcode'
            },
            follow_redirects=True
        )
        self.assertIn(
            b"Your passwords do not match.",
            response.data
        )

    def test_reset_confirm_password_required(self):
        """Test confirm password required on password reset."""
        response = self.client.post(
            '/users/reset_password/resetcode',
            data={
                'email': self.email,
                'password': self.new_password,
                'confirm_password': '',
                'code': 'resetcode'
            },
            follow_redirects=True
        )
        self.assertIn(
            b"Please confirm your password.",
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
                    'confirm_password': self.new_password,
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
                    'confirm_password': '1234',
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Password must be at least eight characters long.',
                response.data
            )

    def test_password_confirm_for_edit(self):
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/password',
                data={
                    'password': self.new_password,
                    'confirm_password': '',
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Please confirm your password.',
                response.data
            )

    def test_password_confirm_for_edit(self):
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/password',
                data={
                    'password': self.new_password,
                    'confirm_password': 'different',
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Your passwords do not match.',
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
