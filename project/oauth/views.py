from .model import OAuthSignIn
from flask import redirect, url_for, request, flash, Blueprint, session

oauth_blueprint = Blueprint(
    'oauth', __name__,
    template_folder='templates'
)


@oauth_blueprint.route('/login/<provider>')
def login(provider):
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@oauth_blueprint.route('/authorized/<provider>')
def authorized(provider):
    oauth = OAuthSignIn.get_provider(provider)
    resp = oauth.authorized_response()
    next_url = request.args.get('next') or url_for('pages.home')
    if resp is None:
        flash('We weren\'t able to log you in', 'error')
        return redirect(url_for('users.login'))

    session['oauth_token'] = oauth.get_session_data(resp)
    oauth.get_user()
    return redirect(next_url)


@oauth_blueprint.route("/logout")
def logout():
    session.pop('oauth_token', None)
    return redirect(url_for('pages.home'))
