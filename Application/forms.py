"""
Forms to be used in the application created by Flask-WTF.
"""
from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user

from Application.models import UserBase


class EditProfileForm(FlaskForm):
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')


class EditUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')


class ShareFileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    filename = StringField('Filename', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Share')

    def validate(self, **kwargs):
        if not super().validate():
            return False

        # The given username should exist in the database
        to_user = UserBase.query.filter_by(username=self.username.data).first()
        if not to_user or to_user.id == current_user.id:
            flash('That username does not exist.')
            return False

        if not to_user.verified:
            flash('That user is not verified.')
            return False

        # The given filename should exist in the database
        from_user = UserBase.query.filter_by(id=current_user.id).first()
        file = from_user.uploads.filter_by(filename=self.filename.data).first()
        if not file:
            flash('That file does not exist.')
            return False
        return True


class RenameFileForm(FlaskForm):
    current_filename = StringField('Current Filename', validators=[DataRequired(), Length(min=2, max=20)])
    new_filename = StringField('New Filename', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Rename')

    def validate(self, **kwargs):
        if not super().validate():
            return False

        # The given username should exist in the database
        from_user = UserBase.query.filter_by(id=current_user.id).first()
        file = from_user.uploads.filter_by(filename=self.current_filename.data).first()
        if not file:
            flash('That file does not exist.')
            return False
        return True
