#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Site manager. Runs tests and server from CLI."""

import unittest
import coverage
import os

from flask.ext.script import Manager
from project import app

manager = Manager(app)


@manager.command
def test():
    """Run unit tests."""
    tests = unittest.TestLoader().discover('', pattern='*.py')
    unittest.TextTestRunner(verbosity=2).run(tests)


@manager.command
def cov():
    """Runs the unit tests with coverage."""
    cov = coverage.coverage(
        branch=True,
        include='project/*'
    )
    cov.start()
    tests = unittest.TestLoader().discover('', pattern='*.py')
    unittest.TextTestRunner(verbosity=2).run(tests)
    cov.stop()
    cov.save()
    print('Coverage Summary:')
    cov.report()
    basedir = os.path.abspath(os.path.dirname(__file__))
    covdir = os.path.join(basedir, 'coverage')
    cov.html_report(directory=covdir)
    cov.erase()


if __name__ == '__main__':
    manager.run()
