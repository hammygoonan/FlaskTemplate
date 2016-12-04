#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""WSGI interface."""


from project import create_app

if __name__ == "__main__":
    import logging
    logging.basicConfig(filename='error.log', level=logging.DEBUG)

    application = create_app('config.Production')

    application.run()
