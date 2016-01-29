"""Adds Mailgun support to Flask applications.

Adapted from http://github.com/sleekslush/flask-mailgun"""

import requests


class Mailgun():

    """Interface for Mailgun API."""

    app = None
    mailgun_api = None

    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Creating a new :class:`MailgunApi` object."""
        self.mailgun_api = MailgunApi(
            app.config['MAILGUN_DOMAIN'],
            app.config['MAILGUN_API_KEY']
        )
        self.app = app

    def send_email(self, **kwargs):
        """Send email interface."""
        if not self.mailgun_api:
            raise ValueError('A valid app instance has not been provided')

        return self.mailgun_api.send_email(**kwargs)


class MailgunApi():

    """Mailgun API implentation."""

    def __init__(self, domain, api_key):
        self.domain = domain
        self.api_key = api_key

    def send_email(self, data=None, files=None):
        """Send email useing the Mailgun API.

        :param data: (optional) Dict of values to be sent as 'data'
        :param files: (optional) List of tuples to send.
        :return: :class:`Response <Response>` object
        """
        response = requests.post(self.endpoint, data=data, files=files,
                                 auth=self.auth)
        response.raise_for_status()
        return response

    @property
    def endpoint(self):
        """Return endpoint for messages API call.

        :return: string
        """
        return 'https://api.mailgun.net/v3/{}/messages'.format(self.domain)

    @property
    def auth(self):
        """Mailgun authentication method.

        :return: set
        """
        return ('api', self.api_key)
