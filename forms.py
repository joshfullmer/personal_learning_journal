from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, DateTimeField, IntegerField,
                     TextAreaField)
from wtforms.validators import (DataRequired, Email, ValidationError, Length,
                                EqualTo, Optional, Regexp)

from models import User


def name_exists(form, field):
    if User.select().where(User.username == field.data).exists():
        raise ValidationError("User with that name already exists.")


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError("User with that email already exists.")


class SignupForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message=("Username should be one work, "
                         "letters, numbers and underscores only.")
            ),
            name_exists
        ]
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(),
            email_exists
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=2),
            EqualTo('password2', message='Passwords must match')
        ]
    )
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class EntryForm(FlaskForm):
    title = StringField('Title')
    date = DateTimeField(
        'Date (optional)',
        validators=[Optional()],
        format="%m/%d/%Y",
    )
    time_spent = IntegerField('Time Spent')
    what_you_learned = TextAreaField('What You Learned')
    resources_to_remember = TextAreaField('Resources to Remember')


class DeleteEntryForm(FlaskForm):
    pass
