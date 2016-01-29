from flask import Blueprint, render_template

from project.users.forms import RegistationForm

pages_blueprint = Blueprint(
    'pages', __name__,
    template_folder='templates'
)


@pages_blueprint.route('/')
def home():
    form = RegistationForm()
    return render_template('home.html', form=form)
