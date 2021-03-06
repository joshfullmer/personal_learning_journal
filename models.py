import datetime

from flask_bcrypt import generate_password_hash
from flask_login import UserMixin
from peewee import *
from slugify import slugify


DATABASE = SqliteDatabase('journal.db')


class User(UserMixin, Model):
    """Standard user model for logging in"""
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=64)
    created_date = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)

    class Meta:
        database = DATABASE
        order_by = ('-created_date', )

    @classmethod
    def create_user(cls, username, email, password, admin=False):
        """Create user with hashed password"""
        try:
            with DATABASE.transaction():
                cls.create(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    is_admin=admin,
                )
        except IntegrityError:
            raise ValueError("User already exists")


class Entry(Model):
    """Holds data related to a learning journal entry"""
    title = CharField(max_length=100)
    date = DateTimeField(default=datetime.datetime.now)
    time_spent = IntegerField()
    what_you_learned = TextField()
    resources_to_remember = TextField()
    user = ForeignKeyField(User, backref='entries')
    slug = CharField(max_length=100, unique=True)

    class Meta:
        database = DATABASE
        order_by = ('-date', )

    @classmethod
    def create_entry(cls, title, date, time_spent, what_you_learned,
                     resources_to_remember, user):
        """Creates an entry from given data.  Handles slug creation and the
        date of creation"""

        # Check if slug already exists in database
        # If it does, adds a sequential number to the end of the slug until
        # it's a unique slug
        slug = slugify(title)
        existing_slugs = []
        for s in cls.select(cls.slug).where(cls.slug.contains(slug)):
            existing_slugs.append(s.slug)
        if existing_slugs:
            slug_check = slug
            slug_num = 1
            while slug_check in existing_slugs:
                slug_check = slug + str(slug_num)
                slug_num += 1
            slug = slug_check
        cls.create(
            title=title,
            date=date,
            time_spent=time_spent,
            what_you_learned=what_you_learned,
            resources_to_remember=resources_to_remember,
            user=user,
            slug=slug,
        )

    def get_tags(self):
        """Returns a peewee modelselect with all of the entry's tags"""
        tags = (Tag.select()
                   .join(EntryTag)
                   .join(Entry)
                   .where(Entry.id == self.id))
        return tags


class Tag(Model):
    """Contains data for the tags"""
    name = CharField(max_length=50)

    class Meta:
        database = DATABASE
        order_by = ('name', )


class EntryTag(Model):
    """Holds the relationship between entries and tags"""
    entry = ForeignKeyField(Entry, backref='entries')
    tag = ForeignKeyField(Tag, backref='tags')

    class Meta:
        database = DATABASE


def initialize():
    DATABASE.connect()
    DATABASE.create_tables([User, Entry, Tag, EntryTag], safe=True)
    DATABASE.close()
