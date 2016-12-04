#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

from mock import patch
from mock import MagicMock

from flask_oauthlib.client import OAuthRemoteApp
from flask import url_for, session
from flask_login import current_user

from project import db, random_str
from tests.base import BaseTestCase
from project.oauth.model import OAuthSignIn
from project.users.models import User


class OauthTestCase(BaseTestCase):

    """Application wide tests."""

    def test_google_subclass(self):
        oauth = OAuthSignIn.get_provider('google')
        self.assertEqual('GoogleSignIn', oauth.__class__.__name__)

    def test_twitter_subclass(self):
        oauth = OAuthSignIn.get_provider('twitter')
        self.assertEqual('TwitterSignIn', oauth.__class__.__name__)

    def test_google_get_callback_url(self):
        oauth = OAuthSignIn.get_provider('google')
        self.assertEqual(
            url_for('oauth.authorized', provider='google', _external=True),
            oauth.get_callback_url()
        )

    @patch.object(OAuthRemoteApp, 'authorized_response')
    def test_authorized_response(self, authorized_response_mock):
        authorized_response_mock.return_value = {'test': 'dict'}
        oauth = OAuthSignIn.get_provider('google')
        response = oauth.authorized_response()
        self.assertEqual({'test': 'dict'}, response)

    def test_get_token(self):
        session['oauth_token'] = 'test token'
        self.assertEqual('test token', OAuthSignIn.get_token())

    def test_google_authorize(self):
        oauth = OAuthSignIn.get_provider('google')
        response = oauth.authorize()
        self.assertEqual(302, response.status_code)

    def test_redirect_to_google(self):
        response = self.client.get(
            url_for('oauth.login', provider='google'),
            follow_redirects=False
        )
        self.assertIn('google', response.location)

    def test_redirect_to_twitter(self):
        # response = self.client.get(
        #     url_for('oauth.login', provider='twitter'),
        #     follow_redirects=False
        # )
        # self.assertIn('twitter', response.location)
        pass

    def test_get_session_data(self):
        oauth = OAuthSignIn.get_provider('google')
        session_data = oauth.get_session_data({'access_token': 'test'})
        self.assertEqual(('test', ''), session_data)

    @patch.object(OAuthRemoteApp, 'get')
    def test_get_user_data(self, get_mock):
        get_mock.return_value = mock_get_response = MagicMock()
        mock_get_response.data = {'name': 'Test Name',
                                  'email': 'test@gmail.com'}
        session['oauth_token'] = 'test'

        oauth = OAuthSignIn.get_provider('google')
        data = oauth.get_user_data()
        self.assertEqual(data['name'], 'Test Name')
        self.assertEqual(data['email'], 'test@gmail.com')

    @patch.object(OAuthRemoteApp, 'get')
    def test_get_user_creates_new_and_logs_in(self, get_mock):
        user = User.query.filter_by(email='test@gmail.com').first()
        self.assertIsNone(user)

        get_mock.return_value = mock_get_response = MagicMock()
        mock_get_response.data = {'name': 'Test Name',
                                  'email': 'test@gmail.com'}
        session['oauth_token'] = 'test'

        oauth = OAuthSignIn.get_provider('google')
        oauth.get_user()
        user = User.query.filter_by(email='test@gmail.com').first()
        self.assertTrue(user)
        self.assertTrue(current_user.is_authenticated)

    @patch.object(OAuthRemoteApp, 'get')
    def test_get_user_logins_in(self, get_mock):
        get_mock.return_value = mock_get_response = MagicMock()
        mock_get_response.data = {'name': 'Test Name',
                                  'email': 'test_1@example.com'}
        session['oauth_token'] = 'test'

        oauth = OAuthSignIn.get_provider('google')
        oauth.get_user()
        self.assertTrue(current_user.is_authenticated)

    @patch.object(OAuthRemoteApp, 'authorized_response')
    def test_cant_log_in(self, authorized_response_mock):
        authorized_response_mock.return_value = None

        with self.client:
            response = self.client.get(
                url_for('oauth.authorized', provider='google'),
                follow_redirects=True
            )
            self.assertIn('We weren\\\'t able to log you in',
                          str(response.data))

    def test_logout(self):
        with self.client:
            session['oauth_token'] = 'test token'
            self.client.get(url_for('oauth.logout'))
            self.assertNotIn('auth_token', session)

    @patch.object(OAuthRemoteApp, 'get')
    def test_is_google_in_db(self, get_mock):

        get_mock.return_value = mock_get_response = MagicMock()
        mock_get_response.data = {'name': 'Test Name',
                                  'email': 'test@gmail.com'}
        session['oauth_token'] = 'test'

        oauth = OAuthSignIn.get_provider('google')
        oauth.get_user()
        user = User.query.filter_by(email='test@gmail.com').first()
        self.assertTrue(user.google)

    @patch.object(OAuthRemoteApp, 'get')
    def test_is_not_facebook_in_db(self, get_mock):

        get_mock.return_value = mock_get_response = MagicMock()
        mock_get_response.data = {'name': 'Test Name',
                                  'email': 'test@gmail.com'}
        session['oauth_token'] = 'test'

        oauth = OAuthSignIn.get_provider('google')
        oauth.get_user()
        user = User.query.filter_by(email='test@gmail.com').first()
        self.assertFalse(user.facebook)

    @patch.object(OAuthRemoteApp, 'get')
    def test_user_cant_edit_email(self, get_mock):
        password = random_str(30)
        user = User('Testname', 'test_1@gmail.com', password, None,
                    True)
        db.session.add(user)
        db.session.commit()
        with self.client:
            self.login('test_1@gmail.com', password)
            response = self.client.get(url_for('users.edit'))
            self.assertIn(
                '<input type="hidden" name="email" '
                'value="test_1@gmail.com" />',
                str(response.data)
            )
            self.assertNotIn(
                'Password',
                str(response.data)
            )
