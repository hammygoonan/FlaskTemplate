#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Base testing module that other tests extend from."""

from datetime import datetime
from datetime import timedelta
from flask_testing import TestCase
from flask import url_for

from project import create_app
from project import db
from project import random_str
from project.users.models import User
from project.users.models import ResetPassword


class BaseTestCase(TestCase):

    """A base test case."""

    def create_app(self):
        """Create app for tests."""
        return create_app('config.Test')

    def setUp(self):
        """Setup tests."""
        db.create_all()
        self.create_users()

        """Setup User tests."""
        self.email = 'test_1@example.com'
        self.password = 'password1'

        self.new_email = 'new@example.com'
        self.new_password = 'new_password'

        self.other_email = 'test_3@example.com'
        self.other_password = 'password3'

        self.err_email = 'error@example.com'
        self.err_password = 'abc'

    def tearDown(self):
        """Tear down tests."""
        db.session.remove()
        db.drop_all()

    def create_users(self):
        user1 = User(
            'Test User One', 'test_1@example.com', 'password1', None
        )
        db.session.add(user1)
        user2 = User(
            'Test User Two', 'test_2@example.com', 'password2', None
        )
        db.session.add(user2)
        user3 = User(
            'Test User Three', 'test_3@example.com', 'password3', None
        )
        db.session.add(user3)
        user4 = User(
            'Test User Four', 'test_4@example.com', 'password4', None
        )
        db.session.add(user4)
        user5 = User(
            'Test User Five', 'test_5@example.com', 'password5', None
        )
        db.session.add(user5)
        unconfirmed = User(
            'Unconfirmed User', 'unconfirmed@example.com',
            'unconfirmed_password', random_str(30)
        )
        db.session.add(unconfirmed)

        db.session.add(
            ResetPassword(
                user1, 'resetcode', datetime.utcnow() + timedelta(hours=24)
            )
        )
        db.session.add(
            ResetPassword(
                user2, 'resetcode2', datetime.utcnow() - timedelta(hours=24)
            )
        )

        db.session.commit()

    # helper methods
    def login(self, email=None, password=None):
        """Login to site."""
        if email is None:
            email = self.email
        if password is None:
            password = self.password
        return self.client.post(
            url_for('users.login'),
            follow_redirects=True,
            data={
                'email': email,
                'password': password
            },
        )
