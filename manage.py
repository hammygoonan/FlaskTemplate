#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import unittest
import coverage

from project import create_app

if len(sys.argv) < 1:
    raise AttributeError('Please provide an option')

if sys.argv[1] not in ['runserver', 'test', 'coverage']:
    raise AttributeError('Option not supported')


if sys.argv[1] == 'runserver':
    app = create_app('config.Development')
    app.run()

if sys.argv[1] == 'test':
    tests = unittest.TestLoader().discover('tests', pattern='*.py')
    unittest.TextTestRunner(verbosity=1).run(tests)

if sys.argv[1] == 'coverage':
    cov = coverage.coverage(
        branch=True,
        include='project/*'
    )
    cov.start()
    tests = unittest.TestLoader().discover('tests', pattern='*.py')
    unittest.TextTestRunner(verbosity=2).run(tests)
    cov.stop()
    cov.save()
    print('Coverage Summary:')
    cov.report()
    basedir = os.path.abspath(os.path.dirname(__file__))
    covdir = os.path.join(basedir, 'coverage')
    cov.html_report(directory=covdir)
    cov.erase()
