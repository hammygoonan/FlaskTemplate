from flask import Blueprint
from flask import render_template

from project.users.forms import RegistationForm

pages_blueprint = Blueprint(
    'pages', __name__,
    template_folder='templates'
)


@pages_blueprint.route('/')
def home():
    form = RegistationForm()
    return render_template('pages/home.html', form=form)
