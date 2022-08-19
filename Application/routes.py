import os
import shutil

import cv2
import numpy as np
from flask import render_template, request, url_for, redirect, flash, send_from_directory
from flask_login import login_user, logout_user, current_user, login_required
import flask_wtf as wtf
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

from Application import app, encryptor
from Application.forms import *
from Application.forms import RegistrationForm
from Application.database import *



@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template('index.html', title='Home Page')


@app.route('/about')
def about_page():
    return render_template('about.html', title='About')


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now()
        db.session.commit()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'), code=302)

    form = LoginForm()
    if form.validate_on_submit():
        user_login = UserBase.query.filter_by(username=form.username.data).first()
        print(user_login)
        if user_login is None or not user_login.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')

        try:
            if authenticate(user_login.id):
                # Adding log in to the database
                add_log(user_login.id, 'login_success')

                login_user(user_login, remember=form.remember.data)

                # Increment the login count
                user_login.login_count += 1
                db.session.commit()

                flash('You are now logged in')
                return redirect(url_for('index'))
            else:
                # Adding log in to the database
                add_log(user_login.id, 'login_failed')
                flash('Face authentication failed')
                return redirect(url_for('login'))
        except Exception as e:
            # Adding log in to the database
            add_log(user_login.id, 'login_failed')
            flash('Face authentication failed')
            print(e)
            return redirect(url_for('login'))
    return render_template('login.html', form=form, title='Sign In')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form: RegistrationForm = RegistrationForm()
    if form.validate_on_submit():
        user_id = add_user(form.username.data, form.email.data, form.password.data, form.job_id.data)
        flash('Congratulations, you are now a registered user, please add your face for authentication')
        return redirect(url_for('add_authentication', user_id=user_id))


    return render_template('register.html', form=form, title='Register')


@app.route('/logout')
@login_required
def logout():
    # Adding log out to the database
    add_log(current_user.id, 'logout')
    logout_user()
    print("Logged out.")
    return redirect(url_for('index'))


@app.route('/user/<username>')
@login_required
def user(username):
    user_profile = UserBase.query.filter_by(username=username).first_or_404()
    user_profile = user_profile.serialize()
    print(user_profile)
    return render_template('user.html', user=user_profile, title='User Profile')


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        current_user.last_updated = datetime.now()
        db.session.commit()
        flash('Your changes have been saved.')

        # Adding log to the database
        add_log(current_user.id, 'edit_profile')
        return redirect(url_for('user', username=current_user.username))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me

    return render_template('edit_profile.html', form=form, title='Edit Profile')


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Upload': Upload, 'Log': Log, 'User': User, 'UserBase': UserBase, 'encryptor': encryptor, 'delete_all_users': delete_all_users}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['UPLOAD_EXTENSIONS']


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        f = request.files.get('file')
        # Get size of the file
        size = len(f.read())
        f.seek(0)

        if f and allowed_file(f.filename):
            filename = secure_filename(f.filename)
            file_location = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(file_location)
            try:
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Encrypting the file
                encryptor.encrypt_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Add the upload to the database with size in bytes
                add_upload(current_user.id, filename, size)

                # Adding log to the database
                add_log(current_user.id, 'upload_file')
                flash('File uploaded successfully')

                return redirect(url_for('user', username=current_user.username))
            except Exception as e:
                print(e)
                flash('Failed to upload file')
                return redirect(url_for('upload_file'))
            finally:
                f.close()
        else:
            flash('File type not allowed.')
            return redirect(url_for('upload_file'))

    return render_template('upload_file.html', title='Upload')


@app.route('/download_file/<filename>', methods=['GET', 'POST'])
@login_required
def download_file(filename):
    filename = secure_filename(filename)
    filename_encrypted = filename + '.enc'
    try:
        # Copy the file to the temp folder
        shutil.copy(os.path.join(app.config['UPLOAD_FOLDER'], filename_encrypted), app.config['TEMP_FOLDER'])

        # Decrypt the file
        encryptor.decrypt_file(os.path.join(app.config['TEMP_FOLDER'], filename_encrypted))

        # Add the log to the database
        add_log(current_user.id, 'download_file')
        return send_from_directory(app.config['TEMP_FOLDER'], filename, as_attachment=True)

    except Exception as e:
        print(e)
        flash('Failed to download file')
        return redirect(url_for('user', username=current_user.username))


@app.route('/delete_file/<filename>', methods=['GET', 'POST'])
@login_required
def delete_file(filename):
    # Check if the file exists
    filename += '.enc'
    if request.method == 'POST' and filename in os.listdir(app.config['UPLOAD_FOLDER']):
        # Delete the file from the database
        upload = Upload.query.filter_by(filename=filename).first_or_404()
        db.session.delete(upload)
        db.session.commit()
        # Delete the file from the upload folder
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File deleted successfully.')

        # Adding log to the database
        add_log(current_user.id, 'delete_file')

    else:
        flash('File does not exist.')

    return redirect(url_for('user', username=current_user.username))


# The admin home page containing all users for admins
@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if current_user.type == 'admin':
        user_list = User.query.all()
        user_list = [user_.serialize() for user_ in user_list]
        return render_template('users.html', users=user_list, title='Users')

    return redirect(url_for('index'))


# The page containing activity of a user for admins
@app.route('/activity/<username>', methods=['GET', 'POST'])
@login_required
def activity(username):
    if current_user.type == 'admin':
        user_id = UserBase.query.filter_by(username=username).first_or_404().id

        log_list = Log.query.filter_by(user_id=user_id).all()
        log_list.reverse()
        log_list = [log.serialize() for log in log_list]

        return render_template('activity.html', logs=log_list, title='Activity of ' + username)

    return redirect(url_for('index'))


# Edit user details for admins
@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    if current_user.type == 'admin':
        form = EditUserForm()
        if form.validate_on_submit():
            try:
                edit_user(username, form.email.data, form.about_me.data)
                flash('Your changes have been saved.')
                add_log(current_user.id, 'edit_user')
            except Exception as e:
                print(e)
                add_log(current_user.id, 'edit_user_failed')
                return redirect(url_for('edit_user', username=username))

            return redirect(url_for('users'))

        elif request.method == 'GET':
            user_id = UserBase.query.filter_by(username=username).first_or_404().id
            form.email.data = UserBase.query.filter_by(id=user_id).first_or_404().email
            form.about_me.data = UserBase.query.filter_by(id=user_id).first_or_404().about_me
        return render_template('edit_user.html', form=form, title='Edit User')

    return redirect(url_for('index'))


@app.route('/all_logs', methods=['GET', 'POST'])
@login_required
def all_logs():
    if current_user.type == 'admin':
        log_list = Log.query.all()
        log_list = sorted(log_list, key=lambda x: x.done_at, reverse=True)
        # use serializer
        log_list = [log.serialize() for log in log_list]
        return render_template('all_logs.html', logs=log_list, title='All Logs')

    return redirect(url_for('index'))


@app.route('/delete_user/<username>', methods=['GET', 'POST'])
@login_required
def delete_user(username):
    if current_user.type == 'admin':
        try:
            delete_user(username)
            flash('User deleted successfully.')
            # adding log to the database
            add_log(current_user.id, 'delete_user')
            return redirect(url_for('users'))
        except Exception as e:
            flash('Error deleting user.')
            print(e)
    return redirect(url_for('index'))


@app.route('/add_authentication/<user_id>', methods=['GET', 'POST'])
@login_required
def add_authentication(user_id):
    # Check if the user is already authenticated
    if current_user.authenticated:
        flash('You are already authenticated.')
        return redirect(url_for('index'))

    if current_user.id != int(user_id):
        flash('Invalid Request!!')
        return redirect(url_for('index'))

    if request.method == 'POST':
        fs = request.files.get('snap')
        if fs:
            # Convert the fs to a numpy array
            img = np.fromstring(fs.read(), np.uint8)
            img = cv2.imdecode(img, cv2.IMREAD_COLOR)

            # Add authentication
            try:
                result = add_authentication(user_id, img)
                if result == "Success":
                    flash('Authentication Successful')
                    add_log(current_user.id, 'add_authentication')
                    return result
                else:
                    flash('Authentication Failed')
                    add_log(current_user.id, 'add_authentication_failed')
                    return result
            except Exception as e:
                print(e)
                flash('Error adding authentication.')
                return "Error" + str(e)
        else:
            return "No file"
    return render_template('add_authentication.html', title='Add Authentication')


@app.route('/authenticate/<user_id>', methods=['GET', 'POST'])
@login_required
def authenticate(user_id):
    if current_user.id != int(user_id):
        flash('Invalid Request!!')
        return redirect(url_for('index'))

    if request.method == 'POST':
        fs = request.files.get('snap')
        if fs:
            # Convert the fs to a numpy array
            img = np.fromstring(fs.read(), np.uint8)
            img = cv2.imdecode(img, cv2.IMREAD_COLOR)

            # Add authentication
            try:
                result = authenticate(user_id, img)
                if result == "Success":
                    flash('Authentication Successful')
                    add_log(current_user.id, 'login')
                    return result
                else:
                    flash('Authentication Failed')
                    add_log(current_user.id, 'login_failed')
                    return result
            except Exception as e:
                print(e)
                flash('Error authenticating.')
                return "Error" + str(e)
    return render_template('authentication.html', title='Authentication')

