from flask import Flask, render_template, flash, redirect, url_for, g, abort
from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, login_user, logout_user, login_required,
                         current_user)

import datetime
import forms
import models


DEBUG = True
PORT = 8000
HOST = '0.0.0.0'

# Flask app initiation
app = Flask(__name__)
app.secret_key = ("It's the questions we can't answer that teach us the most."
                  "They teach us how to think. If you give a man an answer, "
                  "all he gains is a little fact. "
                  "But give him a question and he'll look "
                  "for his own answers.")

# User login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'error'


@login_manager.user_loader
def load_user(user_id):
    """Allow login manager to access the User model"""
    try:
        return models.User.get(models.User.id == user_id)
    except models.DoesNotExist:
        return None


@app.before_request
def before_request():
    """Connect to the database before each request."""
    g.db = models.DATABASE
    g.db.connect()
    g.user = current_user


@app.after_request
def after_request(response):
    """Close the database connection after each request."""
    g.db.close()
    return response


@app.route('/')
def index():
    """Show the most recent 5 entries by all users"""
    entries = models.Entry.select().limit(5).order_by(models.Entry.date.desc())
    return render_template('index.html', entries=entries, view_all=True)


@app.route('/entries')
def entry_list():
    """Show all entries"""
    entries = models.Entry.select().order_by(models.Entry.date.desc())
    return render_template('index.html', entries=entries, view_all=False)


@app.route('/entries/<slug>')
def view_entry(slug):
    """Show entry by given slug"""
    entry = models.Entry.select().where(models.Entry.slug == slug).get()
    if not entry:
        abort(404)
    return render_template('detail.html', entry=entry)


@app.route('/entries/by/<username>')
def user_entries(username):
    """Show all entries by a single user by username"""
    try:
        entries = (models.User.select()
                              .where(models.User.username == username)
                              .get()
                              .entries
                              .order_by(models.Entry.date.desc()))
    except models.DoesNotExist:
        abort(404)
    return render_template('index.html', entries=entries, view_all=True)


@app.route('/entry', methods=('GET', 'POST'))
@login_required
def entry():
    """Create an entry"""
    form = forms.EntryForm()
    if form.validate_on_submit():
        # The create_entry method assigns a slug
        models.Entry.create_entry(
            user=g.user._get_current_object(),
            title=form.title.data.strip(),
            date=(form.date.data or datetime.datetime.now()),
            time_spent=form.time_spent.data,
            what_you_learned=form.what_you_learned.data.strip(),
            resources_to_remember=form.resources_to_remember.data.strip(),
        )
        flash("Entry created! Thanks!", "success")
        return redirect(url_for('index'))
    return render_template('entry.html', form=form)


@app.route('/entries/<slug>/edit/', methods=('GET', 'POST'))
@login_required
def edit_entry(slug):
    """Edit an existing entry using a slug as lookup"""
    entry = models.Entry.select().where(models.Entry.slug == slug).get()
    form = forms.EntryForm(obj=entry)
    if not entry:
        abort(404)
    if form.validate_on_submit():
        # Entry retains the same slug as-is
        q = models.Entry.update(
            user=g.user._get_current_object(),
            title=form.title.data.strip(),
            date=(form.date.data or datetime.datetime.now()),
            time_spent=form.time_spent.data,
            what_you_learned=form.what_you_learned.data.strip(),
            resources_to_remember=form.resources_to_remember.data.strip(),
        ).where(models.Entry.id == entry.id)
        q.execute()
        flash("Entry updated! Thanks!", "success")
        return redirect(url_for('index'))
    return render_template('entry.html', form=form)


@app.route('/entries/<slug>/delete/', methods=('GET', 'POST'))
@login_required
def delete_entry(slug):
    """Delete entry using given slug as lookup"""
    entry = models.Entry.select().where(models.Entry.slug == slug).get()
    form = forms.DeleteEntryForm()
    if form.validate_on_submit():
        models.Entry.delete_by_id(entry.id)
        flash("Entry successfully deleted!", "success")
        return redirect(url_for('entry_list'))
    return render_template('delete.html', entry=entry, form=form)


@app.route('/signup', methods=('GET', 'POST'))
def signup():
    """User signup form"""
    form = forms.SignupForm()
    if form.validate_on_submit():
        flash("You have registered successfully. Thanks!", "success")
        models.User.create_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        return redirect(url_for('index'))
    return render_template('signup.html', form=form)


@app.route('/login', methods=('GET', 'POST'))
def login():
    """User login form"""
    form = forms.LoginForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(models.User.email == form.email.data)
        except models.DoesNotExist:
            flash("Your email or password doesn't match!", "error")
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You've been logged in!", "success")
                return redirect(url_for('index'))
            else:
                flash("Your email or password doesn't match!", "error")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Log out current user"""
    logout_user()
    flash("You've been logged out!  Come back soon!", "success")
    return redirect(url_for('index'))


if __name__ == '__main__':
    models.initialize()
    # Generate default user if they don't exist
    try:
        models.User.create_user(
            username="joshfullmer",
            email="test@test.com",
            password="password",
            admin=True
        )
    except ValueError:
        pass
    app.run(debug=DEBUG, host=HOST, port=PORT)
