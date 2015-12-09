#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Base testing module that other tests extend from."""


from flask.ext.testing import TestCase
from project import app, db
from create_db import create_db


class BaseTestCase(TestCase):

    """A base test case."""

    def create_app(self):
        """Create app for tests."""
        app.config.from_object('config.TestConfig')
        return app

    def setUp(self):
        """Setup tests."""
        create_db()

    def tearDown(self):
        """Tear down tests."""
        db.session.remove()
        db.drop_all()
