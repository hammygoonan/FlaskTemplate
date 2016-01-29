#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

from flask import url_for
from tests.base import BaseTestCase
from flask.ext.login import current_user
from project import bcrypt
from project.users.models import User, ResetPassword


class UsersTestCase(BaseTestCase):

    """User test cases."""

    # Login page
    def test_login_page(self):
        """Test login page."""
        response = self.client.get('/users/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)
        self.assertIn(b'Login</title>', response.data)

    def test_can_login(self):
        """Test user can login."""
        with self.client:
            response = self.login()
            self.assertEqual(response.status_code, 200)
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
        self.assertIn(b'Sign Up', response.data)
        self.assertIn(b'Sign Up</title>', response.data)

    def test_user_cannt_register_without_email(self):
        """Check cannot register without email."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'name': 'John Smith',
                    'email': '',
                    'password': self.other_password,
                    'confirm_password': self.other_password
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
                    'name': 'John Smith',
                    'email': self.new_email,
                    'password': '',
                    'confirm_password': ''
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide a password.',
                          response.data)

    def test_user_cannt_register_without_name(self):
        """Test password is required to register."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'name': '',
                    'email': self.new_email,
                    'password': self.new_password,
                    'confirm_password': ''
                },
                follow_redirects=True
            )
            self.assertIn(b'Please provide a name.',
                          response.data)

    def test_register_password_confirmation(self):
        """Test password confirm."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'name': 'John Smith',
                    'email': self.new_email,
                    'password': self.other_password,
                    'confirm_password': 'different'
                },
                follow_redirects=True
            )
            self.assertIn(b'Your passwords do not match.',
                          response.data)

    def test_register_confirm_password_required(self):
        """Test confirm password required on password reset."""
        response = self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
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

    def test_register_email_validation(self):
        """Test registration has valid email address."""
        with self.client:
            response = self.client.post(
                '/users/register',
                data={
                    'name': 'John Smith',
                    'email': 'not an email address',
                    'password': 'password',
                    'confirm_password': 'password'
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
                    'name': 'John Smith',
                    'email': self.new_email,
                    'password': '1234',
                    'confirm_password': '1234'
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
                'name': 'John Smith',
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn('Please check your email to for a confirmation link',
                      str(response.data))

    def test_new_account_in_database(self):
        """Test new account in database with encrypted password."""
        self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        user = User.query.filter_by(email=self.new_email).first()
        self.assertTrue(user)
        self.assertEqual('John Smith', user.name)
        self.assertTrue(bcrypt.check_password_hash(
            user.password, self.new_password
        ))

    def test_email_is_unique_when_registering(self):
        """Test email is not already in use when registering."""
        self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        response = self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn('There is already an account with this email address',
                      str(response.data))

    # confirm email
    def test_email_confirmation(self):
        """Test email confirmation."""
        self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
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

    def test_connot_login_without_confirmation(self):
        """Test account must be confirmed to login."""
        self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
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
        self.assertIn(b'Forgot Password</title>', response.data)

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
            b'We don\'t have an account with that email address.',
            response.data
        )

    def test_entry_made_in_forgot_password_database(self):
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

    def test_flash_message_for_forgot_password(self):
        """Test emai reset page."""
        response = self.client.post(
            '/users/forgot_password',
            data={
                'email': self.email,
            },
            follow_redirects=True
        )
        self.assertIn(
            'A password reset link has been emailed to you, please check '
            'your email.',
            str(response.data)
        )

    # reset password

    def test_reset_password_page_exists(self):
        """Confirm password reset page exists."""
        response = self.client.get('/users/reset_password/resetcode')
        self.assert200(response)
        self.assertIn(b'Reset Password', response.data)
        self.assertIn(b'Reset Password</title>', response.data)

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
            b'We don\'t have that email address in our system.',
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
            self.assertIn(b'Edit your details', response.data)
            self.assertIn(b'Edit your password', response.data)
            self.assertIn(b'Edit details</title>', response.data)

    def test_user_can_change_email(self):
        """Test the user can update email."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/details',
                data={
                    'name': 'Test User One',
                    'email': self.new_email,
                },
                follow_redirects=True
            )
            self.assertTrue(current_user.email == self.new_email)
            self.assertIn(
                b'Your details have been updated.',
                response.data
            )

    def test_user_can_change_name(self):
        """Test the user can update email."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/details',
                data={
                    'name': 'Test User Two',
                    'email': self.email,
                },
                follow_redirects=True
            )
            self.assertTrue(current_user.name == 'Test User Two')
            self.assertIn(
                b'Your details have been updated.',
                response.data
            )

    def test_email_required_for_edit(self):
        """Test email required for update."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/details',
                data={
                    'name': 'Test User Two',
                    'email': ''
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Please provide an email address.',
                response.data
            )

    def test_name_required_for_edit(self):
        """Test the user name required for update."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/details',
                data={
                    'name': '',
                    'email': self.new_email,
                },
                follow_redirects=True
            )
            self.assertIn(
                b'Please provide a name.',
                response.data
            )

    def test_email_unique_when_editing(self):
        """Test that email being edited is unique and email is not updated."""
        with self.client:
            self.login()
            response = self.client.post(
                '/users/edit/details',
                data={
                    'name': 'Test User One',
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
                '/users/edit/details',
                data={
                    'name': 'Test User One',
                    'email': 'Invalidemailaddress'
                },
                follow_redirects=True
            )
            # display flash message
            self.assertIn(b'Please provide a valid email address.',
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

    def test_password_are_same_for_edit(self):
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

    # Delete
    def test_delete_is_login_protected(self):
        response = self.client.post(
            'users/delete',
            follow_redirects=True
        )
        self.assertIn(b'<h1>Login', response.data)

    def test_delete_must_be_post_request(self):
        response = self.client.get('users/delete')
        self.assertEqual(405, response.status_code)

    def test_user_is_deleted(self):
        self.assertIsNotNone(User.query.get(1))
        with self.client:
            self.login()
            self.client.post('users/delete')
        self.assertIsNone(User.query.get(1))

    def test_redirect_on_login(self):
        with self.client:
            response = self.client.get(
                url_for('users.edit')
            )
            self.assertIn('next=%2Fusers%2Fedit', response.location)
            self.client.get('/users/login?next=/users/edit')
            response = self.client.post(
                'users/login',
                data={
                    'email': self.email,
                    'password': self.password
                },
            )
            self.assertRedirects(response, url_for('users.edit'))

    # resend authorisation
    def test_resend_authorisation_if_logging_into_unconfirmed(self):
        with self.client:
            response = self.login(
                'unconfirmed@example.com', 'unconfirmed_password')
        self.assertIn(
            url_for('users.resend_confirmation') +
                    '?email=unconfirmed@example.com',
            str(response.data))

    def test_resend_authorisation_link_when_signup(self):
        response = self.client.post(
            '/users/register',
            data={
                'name': 'John Smith',
                'email': self.new_email,
                'password': self.new_password,
                'confirm_password': self.new_password
            },
            follow_redirects=True
        )
        self.assertIn(
            url_for('users.resend_confirmation') +
                    '?email=' + self.new_email,
            str(response.data))

    def test_resend_link(self):
        response = self.client.get(
            url_for('users.resend_confirmation') +
                    '?email=unconfirmed@example.com',
            follow_redirects=True
        )
        self.assertIn(
            'Your email confirmation has been resent.', str(response.data))
