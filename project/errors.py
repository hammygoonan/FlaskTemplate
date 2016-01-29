# -*- coding: utf-8 -*-
""" errors.py """
import logging
from logging import FileHandler
from logging.handlers import SMTPHandler
from datetime import datetime

from flask import current_app, Markup, render_template, request
from werkzeug.exceptions import default_exceptions, HTTPException


class ErrorHandler():
    def __init__(self, app):
        # load up info logger
        self.info_logger(app)
        # add excption handler to all default_exceptions
        for exception in default_exceptions:
            app.register_error_handler(exception, self.error_handler)
        # add error_handler to all Exceptions
        app.register_error_handler(Exception, self.error_handler)
        # add handler
        error_mailhost = app.config['ERROR_MAILHOST']
        error_email_to = app.config['ERROR_EMAIL_TO']
        error_email_from = app.config['ERROR_EMAIL_FROM']
        error_email_credentials = app.config['ERROR_EMAIL_CREDENTIALS']
        file_handler = FileHandler('error.log')
        smtp_handler = SMTPHandler(
            mailhost=error_mailhost,
            fromaddr=error_email_to,
            toaddrs=[error_email_from],
            subject='Project Error',
            credentials=error_email_credentials
        )
        app.logger.addHandler(file_handler)
        app.logger.addHandler(smtp_handler)

    @staticmethod
    def error_handler(error):
        msg = """{}
{} - Request resulted in {}
Path: {} | IP: {}
User-Agent: {}
{}"""
        msg = msg.format(
            "="*50, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            error, request.path,
            request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
            request.headers.get('User-Agent'), "="*50)
        current_app.logger.warning(msg, exc_info=error)

        if isinstance(error, HTTPException):
            description = error.get_description(request.environ)
            code = error.code
            name = error.name
        else:
            description = ("We encountered an error "
                           "while trying to fulfill your request")
            code = 500
            name = 'Internal Server Error'

        templates = ['errors/{}.html'.format(code), 'errors/generic.html']
        return render_template(templates,
                               code=code,
                               name=name,
                               description=Markup(description),
                               error=error)

    def info_logger(self, app):
        file_handler = FileHandler('info.log')
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
