#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""WSGI interface."""


from project import create_app

app = create_app('config.DevelopmentConfig')

if __name__ == "__main__":
    app.run()
