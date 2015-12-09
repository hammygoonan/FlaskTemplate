#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Site manager. Runs tests and server from CLI."""

import unittest
from flask.ext.script import Manager
from project import app

manager = Manager(app)


@manager.command
def test():
    """Run unit tests."""
    tests = unittest.TestLoader().discover('', pattern='*.py')
    unittest.TextTestRunner(verbosity=2).run(tests)

if __name__ == '__main__':
    manager.run()
