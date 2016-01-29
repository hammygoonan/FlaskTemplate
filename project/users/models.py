from project import db, bcrypt


class User(db.Model):

    """User model."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    token = db.Column(db.String)
    google = db.Column(db.Boolean)
    facebook = db.Column(db.Boolean)

    def __init__(self, name, email, password, token, google=False,
                 facebook=False):
        """Initialise model."""
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.token = token
        self.google = google
        self.facebook = facebook

    def is_authenticated(self):
        """User validated if account has been confirmed."""
        return True

    def is_active(self):
        """All users are automatically active."""
        if self.token is None:
            return True
        return False

    def is_anonymous(self):
        """No anonymous users."""
        return False

    def get_id(self):
        """Make sure id returned is unicode."""
        return self.id

    def __repr__(self):
        """Representation."""
        return '<user {}>'.format(self.email)


class ResetPassword(db.Model):

    """Reset Password model."""

    __tablename__ = "reset"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    code = db.Column(db.String)
    expires = db.Column(db.DateTime)

    user = db.relationship('User')

    def __init__(self, user, code, expires):
        """Initialise model."""
        self.user = user
        self.code = code
        self.expires = expires

    def __repr__(self):
        """Representation."""
        return '<user {}>'.format(self.code)
