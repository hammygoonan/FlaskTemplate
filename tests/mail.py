#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for users module."""

import json

from flask import url_for

from tests.base import BaseTestCase
from project.mail.mail import Mail, MailMessage


class UsersTestCase(BaseTestCase):

    """User test cases."""

    def setUp(self):
        pass

    def test_get_template_file(self):
        message = MailMessage('forgot_password.html')
        self.assertIn('Someone has requested that your password be reset.',
                      message.template)

    def test_error_is_template_file_doent_exist(self):
        with self.assertRaises(FileExistsError):
            MailMessage('test.html')

    def test_get_formatted_message(self):
        message = MailMessage('forgot_password.html')
        message = message.get_formatted_message(
            ['http://example.com', 'http://example.com']
        )
        self.assertIn('<a href="http://example.com">http://example.com</a>',
                      message)

    def test_incorrect_message_format(self):
        message = MailMessage('forgot_password.html')
        with self.assertRaises(Exception):
            message = message.get_formatted_message(
                'http://example.com', 'http://example.com')
        # with self.assertRaises(Exception):
        #     message = message.get_formatted_message(
        #         'http://example.com')
        # with self.assertRaises(Exception):
        #     message = message.get_formatted_message()

    def test_get_message(self):
        mail = Mail()
        response = mail.get_message(
            'forgot_password.html',
            ['http://example.com', 'http://example.com']
        )
        self.assertIn('<a href="http://example.com">http://example.com</a>',
                      response)

    def test_send_email(self):
        mail = Mail()
        response = mail.send_email(
            {
                'to': 'test@example.com',
                'from': 'recieptient@example.com',
                'subject': 'Test Subject',
                'text': 'This is a test message.'
            }
        )
        json_dict = json.loads(response.content.decode('utf-8'))
        self.assertIsInstance(json_dict, dict)
        self.assertEqual(json_dict['message'], "Queued. Thank you.")

    def test_send_forgot_password(self):
        mail = Mail()
        response = mail.send_forgot_password(
            {
                'to': 'test@example.com',
                'from': 'recieptient@example.com',
                'subject': 'Test Subject'
            },
            values=['http://example.com', 'http://example.com']
        )
        json_dict = json.loads(response.content.decode('utf-8'))
        self.assertIsInstance(json_dict, dict)
        self.assertEqual(json_dict['message'], "Queued. Thank you.")

    def test_send_registration(self):
        mail = Mail()
        response = mail.send_registration(
            {
                'to': 'test@example.com',
                'subject': 'Test Subject'
            },
            values=['Test User', 'test_1@example.com', 'test_2@example.com']
        )
        json_dict = json.loads(response.content.decode('utf-8'))
        self.assertIsInstance(json_dict, dict)
        self.assertEqual(json_dict['message'], "Queued. Thank you.")
