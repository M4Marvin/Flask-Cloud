import os

from flask import redirect, url_for, request, Response, flash, render_template, session
from flask_login import current_user, logout_user

from Application import app
from Application.auth import bp
from Application.auth.forms import LoginForm, RegistrationForm
from Application.auth.utils import face_authenticate, init_session, login_user_, add_face_authentication
from Application.database import add_log, add_user
from Application.models import UserBase


@bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        add_log(current_user.id, 'logout')
        logout_user()
    return redirect(url_for('index'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Face authentication
    if request.method == 'POST' and 'face' in request.files:

        image = request.files.get('face')
        user_id = request.form.get('user_id')

        # Authenticate face
        print(f'Authenticating face for user {user_id}')
        status = face_authenticate(image, user_id)

        if status == 200:
            print('Face authentication successful')
            login_user_(user_id)
            if current_user.type == 'user':
                init_session(user_id)
                add_log(user_id, 'login')
            return Response("Success", status=200)
        else:
            print(f'Face authentication failed with status code {status}')
            return Response("Authentication failed", status=status)

    # Username and password authentication
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = UserBase.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                # Don't log the user in if they are not verified
                if user.type == 'user':
                    if not user.verified:
                        flash('Please wait for your account to be verified.')
                        return redirect(url_for('auth.login'))

                return render_template('auth/authenticate.html', user_id=user.id)
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))

        except Exception as e:
            flash('Error: ' + str(e))
            return redirect(url_for('auth.login'))

    return render_template('auth/login.html', title='Login', form=form)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Adding face authentication
    if request.method == 'POST' and 'face' in request.files:
        image = request.files.get('face')
        user_id = request.form.get('user_id')

        status = add_face_authentication(image, user_id)
        if status == 200:
            # Create user upload folder
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            logout_user()
            return Response("Success", status=200)
        else:
            return Response(f"Error: {status}", status=status)

    form = RegistrationForm()
    if form.validate_on_submit():
        user = add_user(form.username.data, form.password.data, form.email.data, form.job_id.data)
        return render_template('auth/add_authentication.html', user_id=user.id, title='Add Authentication')

    return render_template('auth/register.html', title='Register', form=form)

