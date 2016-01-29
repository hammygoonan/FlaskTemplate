#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

from flask import url_for
from project import db
from tests.base import BaseTestCase


class PagesTestCase(BaseTestCase):

    """Application wide tests."""

    def test_home_page(self):
        """General 404 test."""
        response = self.client.get(url_for('pages.home'))
        self.assert200(response)

    def test_logged_in_home_page(self):
        """General 404 test."""
        self.login('test_1@example.com', 'password1')
        response = self.client.get(url_for('pages.home'))
        self.assert200(response)
