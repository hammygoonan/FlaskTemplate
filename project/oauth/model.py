from flask import url_for, session
from flask_oauthlib.client import OAuth
from flask_login import login_user

from project import app, db, random_str
from project.users.models import User


class OAuthSignIn():

    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name

    def authorize(self):
        return self.service.authorize(self.get_callback_url())

    def authorized_response(self):
        return self.service.authorized_response()

    def get_callback_url(self):
        return url_for('oauth.authorized', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(cls, provider_name):
        if cls.providers is None:
            cls.providers = {}
            for provider_class in cls.__subclasses__():
                provider = provider_class()
                cls.providers[provider.provider_name] = provider
        return cls.providers[provider_name]

    @staticmethod
    def get_token(token=None):
        return session.get('oauth_token')

    def get_session_data(self, data):
        pass

    def get_user_data(self):
        return None


class TwitterSignIn(OAuthSignIn):

    def __init__(self):
        super().__init__('twitter')
        oauth = OAuth()
        self.service = oauth.remote_app(
            'twitter',
            base_url='https://api.twitter.com/1/',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            consumer_key=app.config['TWITTER_CUSTOMER_KEY'],
            consumer_secret=app.config['TWITTER_CUSTOMER_SECRET']
        )
        self.service.tokengetter = TwitterSignIn.get_token

    def get_session_data(self, data):
        return (
            data['oauth_token'],
            data['oauth_token_secret']
        )


class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('google')
        oauth = OAuth()
        self.service = oauth.remote_app(
            'google',
            consumer_key=app.config['GOOGLE_CLIENT_ID'],
            consumer_secret=app.config['GOOGLE_CLIENT_SECRET'],
            request_token_params={
                'scope': 'email'
            },
            base_url='https://www.googleapis.com/oauth2/v1/',
            request_token_url=None,
            access_token_method='POST',
            access_token_url='https://accounts.google.com/o/oauth2/token',
            authorize_url='https://accounts.google.com/o/oauth2/auth',
        )
        self.service.tokengetter(GoogleSignIn.get_token)

    def get_session_data(self, data):
        return (
            data['access_token'],
            ''
        )

    def get_user_data(self):
        access_token = session.get('oauth_token')
        token = 'OAuth ' + access_token[0]
        headers = {b'Authorization': bytes(token.encode('utf-8'))}
        data = self.service.get(
            'https://www.googleapis.com/oauth2/v1/userinfo', None,
            headers=headers)
        return data.data

    def get_user(self):
        data = self.get_user_data()
        user = User.query.filter_by(email=data['email']).first()
        if user is None:
            # name, email, random password, no token, is google
            user = User(data['name'], data['email'], random_str(30), None,
                        True)
            db.session.add(user)
            db.session.commit()

        login_user(user)
