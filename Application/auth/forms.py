from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user

from Application.models import UserBase


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    job_id = StringField('Job ID',
                         validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate(self, **kwargs):
        if not super().validate():
            return False

        validate_username(self.username)
        validate_email(self.email)
        return True


class LoginForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


def validate_email(email):
    user = UserBase.query.filter_by(email=email.data).first()
    if user:
        flash('That email is taken. Please choose a different one.')
        return False

    return True


def validate_username(username):
    user = UserBase.query.filter_by(username=username.data).first()
    if user:
        flash('That username is taken. Please choose a different one.')
        return False

    return True
