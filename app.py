from flask import (Flask, render_template, flash, redirect, url_for, g, abort,
                   request)
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
    g.db.connect(reuse_if_open=True)
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


def get_entry_or_404(slug):
    """Similar to the get_object_or_404, but it searches on slug, not ID"""
    try:
        entry = models.Entry.select().where(models.Entry.slug == slug).get()
    except models.DoesNotExist:
        abort(404)
    return entry


@app.route('/entries')
def entry_list():
    """Show all entries"""
    entries = models.Entry.select().order_by(models.Entry.date.desc())
    return render_template('index.html', entries=entries, view_all=False)


@app.route('/entries/<slug>/')
def view_entry(slug):
    """Show entry by given slug"""
    entry = get_entry_or_404(slug)
    entry_tags = (models.Tag.select()
                            .join(models.EntryTag)
                            .join(models.Entry)
                            .where(models.Entry.id == entry.id))
    if not entry:
        abort(404)
    return render_template('detail.html', entry=entry, entry_tags=entry_tags)


@app.route('/entries/by/<username>')
def user_entries(username):
    """Show all entries by a single user by username"""
    try:
        entries = (models.User.select()
                              .where(models.User.username == username)
                              .get()
                              .entries
                              .order_by(models.Entry.date.desc()))
        entry_tags = []
    except models.DoesNotExist:
        abort(404)
    return render_template('index.html',
                           entries=entries,
                           entry_tags=entry_tags,
                           view_all=True)


@app.route('/entries/by/tag/<tag_id>/')
def entries_by_tag(tag_id):
    """Show all entries by the given tag id number"""
    try:
        tag = models.Tag.get(models.Tag.id == tag_id)
    except models.DoesNotExist:
        abort(404)
    entries = (models.Entry.select()
                           .join(models.EntryTag)
                           .join(models.Tag)
                           .where(models.Tag.id == tag_id))
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
    entry = get_entry_or_404(slug)
    form = forms.EntryForm(obj=entry)
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


@app.route('/tags/create/', methods=('GET', 'POST'))
@login_required
def tag():
    """Create a tag"""
    form = forms.TagForm()
    if form.validate_on_submit():
        models.Tag.create(name=form.name.data)
        flash("Tag created!", "success")
        return redirect(url_for('index'))
    return render_template('tag.html', form=form)


@app.route('/entries/<slug>/tags/', methods=('GET', 'POST'))
@login_required
def apply_tag(slug):
    """Applies a tag to the entry using the given slug"""
    form = forms.EntryTagForm(request.form)
    tags = models.Tag.select()
    entry = get_entry_or_404(slug)
    form.tags.choices = [(tag.id, tag.name) for tag in tags]
    if form.validate_on_submit():
        entry_tags = (models.EntryTag.select()
                                     .where(models.EntryTag.entry == entry.id))
        existing_entry_tags = []

        # Check if the tag is already applied
        for entry_tag in entry_tags:
            existing_entry_tags += [entry_tag.tag.id]
        for selection in request.form.getlist('tags'):
            # Skips applying tags if it has already been applied
            if int(selection) in existing_entry_tags:
                continue
            models.EntryTag.create(
                entry=entry.id,
                tag=selection
            )
        flash("Tags applied!", "success")
        return redirect(url_for('view_entry', slug=slug))
    return render_template('apply_tag.html', form=form, tags=tags, slug=slug)


@app.route('/entries/<slug>/tags/remove/', methods=('GET', 'POST'))
@login_required
def remove_tag(slug):
    """Remove slugs from the entry by slug"""
    form = forms.EntryTagForm(request.form)
    entry = get_entry_or_404(slug)
    e_id = entry.id
    entry_tags = (models.EntryTag.select()
                                 .where(models.EntryTag.entry == entry.id))
    entry_tag_ids = [et.tag.id for et in entry_tags]
    tags = models.Tag.select().where(models.Tag.id << entry_tag_ids)
    form.tags.choices = [(tag.id, tag.name) for tag in tags]
    if form.validate_on_submit():
        selections = [int(s) for s in request.form.getlist('tags')]
        tags = models.Tag.select().where(models.Tag.id << selections)
        q = models.EntryTag.delete().where(
            (models.EntryTag.entry == entry) &
            (models.EntryTag.tag << tags)
        )
        q.execute()
        flash("Tags removed", "success")
        return redirect(url_for('view_entry', slug=slug))
    return render_template('remove_tag.html', form=form, tags=tags, slug=slug)


@app.route('/entries/<slug>/delete/', methods=('GET', 'POST'))
@login_required
def delete_entry(slug):
    """Delete entry using given slug as lookup"""
    entry = get_entry_or_404(slug)
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
