#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Sends emails."""


import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from project import app


class Emailer(object):

    """Sends emails."""

    def __init__(self, to, from_, subject, message, html=True):
        """Initialise."""
        self.to = to
        self.from_ = from_
        self.subject = subject
        self.message = self.__getMessage(message, html)

    def __getMessage(self, message, html):
        encoding = 'plain'
        if html:
            encoding = 'html'
        return MIMEText(message, encoding)

    def __smtpSend(self, to, from_, message):
        port = app.config.get('SMTP_PORT')
        smtp_host = app.config.get('SMTP_HOST')
        require_pw = app.config.get('SMTP_REQUIRE_PASSWORD')
        if app.config.get('SMTP_SSL'):
            port = port if port else 465
            smtp = smtplib.SMTP_SSL(smtp_host, port)
        else:
            port = port if port else 25
            smtp = smtplib.SMTP(smtp_host, port)

        if require_pw:
            smtp.login(app.config['SMTP_USER'], app.config['SMTP_PASSWORD'])
        smtp.sendmail(to, from_, message.as_string())
        smtp.quit()

    def send(self):
        """Send email."""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = self.subject
        msg['From'] = self.from_
        msg['To'] = self.to
        msg.attach(self.message)
        self.__smtpSend(self.from_, self.to, msg)
