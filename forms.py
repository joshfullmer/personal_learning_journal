from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, DateTimeField, IntegerField,
                     TextAreaField)
from wtforms.validators import (DataRequired, Email, ValidationError, Length,
                                EqualTo, Optional)

from models import User


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError("User with that email already exists.")


class SignupForm(FlaskForm):
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
        validators=[Optional()]
    )
    time_spent = IntegerField('Time Spent')
    what_you_learned = TextAreaField('What You Learned')
    resources_to_remember = TextAreaField('Resources to Remember')
