#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

from tests.base import BaseTestCase
from project import random_str


class GeneralTestCase(BaseTestCase):

    """Application wide tests."""

    def test_404_page(self):
        response = self.client.get('/notapage')
        self.assert404(response)

    def test_random_string(self):
        string1 = random_str()
        string2 = random_str(30)
        self.assertEqual(10, len(string1))
        self.assertEqual(30, len(string2))
        self.assertTrue(string1 != string2)
