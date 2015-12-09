#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""create_db.py: Create database and a range of dummy data for testing."""


from project import db
from datetime import datetime, timedelta
from project.models import User, ResetPassword


def create_db():
    """Create database for tests."""
    db.create_all()
    user = User('test_1@example.com', 'password')
    user2 = User('test_3@example.com', 'other_password')
    db.session.add(user)
    db.session.add(user2)
    db.session.add(ResetPassword(user, 'resetcode',
                                 datetime.utcnow() + timedelta(hours=24)))
    db.session.add(ResetPassword(user2, 'resetcode2',
                                 datetime.utcnow() - timedelta(hours=24)))
    db.session.commit()
