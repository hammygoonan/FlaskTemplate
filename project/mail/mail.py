import os

from project import mailgun
from project import current_app


class Mail():

    """Send templated emails."""

    def __init__(self):
        self.path = os.path.dirname(__file__)
        self.default_from = current_app.config['MAIL_FROM_DEFAULT']

    @staticmethod
    def send_registration(data, **kwargs):
        """Send new registations email.

        :param data: dictionary of values to send email.
        :param template: path to template file
        :param values: list values for template
        :return: :class:`Response <Response>` object
        """

        mail = Mail()
        if 'text' not in data and 'html' not in data:
            kwargs.setdefault('template', 'registration.html')
            kwargs.setdefault('values', None)
            data['html'] = mail.get_message(
                kwargs['template'],
                kwargs['values']
            )

        return mail.send_email(data)

    @staticmethod
    def send_forgot_password(data, **kwargs):
        """Send competition invitation email.

        :param data: dictionary of values to send email.
        :param template: path to template file
        :param values: list values for template
        :return: :class:`Response <Response>` object
        """

        mail = Mail()
        if 'text' not in data and 'html' not in data:
            kwargs.setdefault('template', 'forgot_password.html')
            kwargs.setdefault('values', None)
            data['html'] = mail.get_message(
                kwargs['template'],
                kwargs['values']
            )
        return mail.send_email(data)

    def get_message(self, template, values=None):
        message = MailMessage(template, values)
        return message.get_formatted_message(values)

    def send_email(self, data):
        data.setdefault('from', self.default_from)
        return mailgun.send_email(data=data)


class MailMessage():

    """Format email templates for sending."""

    def __init__(self, template, values=None):
        self.template = self.get_template_file(template)

    def get_template_file(self, template):
        """Generate formatted message from template.

        :param string: template path
        :return string:
        """
        paths = [
            os.path.dirname(__file__) + '/templates/email/' + template,
            os.path.dirname(__file__) + '/' + template,
            template
        ]
        file_name = None
        for path in paths:
            if os.path.isfile(path):
                file_name = path

        if file_name is None:
            paths = ', '.join(paths)
            raise FileExistsError('None of the following files exist: '
                                  + paths)

        with open(file_name) as f:
            message = f.read()
        return message

    def get_formatted_message(self, values=None):
        """Add values to template string.

        :param list: list of values for template.
        :return string: formatted template file with values inserted.
        """
        if values:
            return self.template.format(*values)
        return self.template


def send_registration(data, **kwargs):
    return Mail.send_registration(data, **kwargs)


def send_forgot_password(data, **kwargs):
    return Mail.send_forgot_password(data, **kwargs)
