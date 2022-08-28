import os
import shutil
from datetime import timedelta

import numpy as np
from flask import render_template, url_for, redirect, flash, send_from_directory, Response, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename

from Application import encryptor
from Application.database import *
from Application.forms import *
from Application.forms import RegistrationForm


@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template('content/index.html', title='Home Page')


@app.route('/about')
def about_page():
    return render_template('content/about.html', title='About')


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now()
        db.session.commit()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'), code=302)

    # Face authentication
    if request.method == "POST" and 'snap' in request.files:
        image = request.files.get('snap')
        user_id = request.form.get('user_id')
        if image is None:
            flash('No image selected', 'danger')
            return Response('No image selected', status=400)
        if user_id is None:
            flash('No user id selected', 'danger')
            return Response('No user id selected', status=400)

        image = np.fromstring(image.read(), np.uint8)
        image = cv2.imdecode(image, cv2.IMREAD_COLOR)

        if verify_image(image):
            if authenticate(user_id, image):
                print(f'Authentication successful for user {user_id}')
                login_user(get_user_by_id(user_id), duration=timedelta(hours=2))
                increment_login_count(user_id)

                # Begin session for user
                if current_user.type == 'user':
                    session['user_id'] = user_id
                    session['num_deletes'] = 0
                    session['num_renames'] = 0
                    session['invalid_requests'] = 0
                    session['init_num_uploads'] = get_user_by_id(user_id).uploads.count()

                # Add log entry
                add_log(user_id, 'login')
                return Response('Authentication successful', status=200)

            else:
                flash('Authentication failed', 'danger')
                return Response('Authentication failed', status=400)

        else:
            flash('Invalid image', 'danger')
            return Response('Invalid image', status=400)

    # Username and password authentication
    form = LoginForm()
    if form.validate_on_submit():

        try:
            user_login = UserBase.query.filter_by(username=form.username.data).first()
            if user_login is None:
                flash('Invalid username or password')
                return redirect(url_for('login'))

            if not user_login.type == 'admin':
                if not user_login.verified:
                    flash('Please wait for verification')
                    return redirect(url_for('login'))

            return render_template('content/authentication.html', title="Face Authorization", user_id=user_login.id)

        except Exception as e:
            flash('Error: ' + str(e), 'danger')
            print(f'Error: {e}')
            return redirect(url_for('login'))

    return render_template('content/login.html', form=form, title='Sign In')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Adding face authentication
    if request.method == "POST" and 'snap' in request.files:
        image = request.files.get('snap')
        user_id = request.form.get('user_id')
        if image is None:
            return Response('No image selected', status=400)
        if user_id is None:
            return Response('No user id selected', status=400)

        image = np.fromstring(image.read(), np.uint8)
        image = cv2.imdecode(image, cv2.IMREAD_COLOR)
        if verify_image(image):
            if authenticate(user_id, image):
                print(f'Face authentication enabled for user {user_id}')

                # Create user upload directory
                user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
                logout_user()

                if not os.path.exists(user_dir):
                    os.makedirs(user_dir)
                return Response('Success', status=200)
            else:
                return Response('Fail', status=400)
        else:
            return Response('Invalid image', status=400)

    # User registration
    form: RegistrationForm = RegistrationForm()
    user_register = None
    if form.validate_on_submit():
        try:
            user_register = add_user(form.username.data, form.password.data, form.email.data, form.job_id.data)
            return render_template('content/add_authentication.html',
                                   title="Add Face Authorization",
                                   user_id=user_register.id)
        except Exception as e:
            flash('Invalid data', 'danger')
            print(e)
            # Delete user if registration fails
            if user_register is not None:
                delete_user(user_register.id)

            return redirect(url_for('register'))

    return render_template('content/register.html', form=form, title='Register')


@app.route('/user/<username>')
@login_required
def user(username):
    # Verify user session
    if not current_user.username == username and not current_user.type == 'admin':
        if not verify_session():
            # Block user if session is invalid
            block_user_db(current_user.id)
            logout_user()
            return redirect(url_for('login'))
    # Block the user if he deleted all files
    if current_user.type == 'user':
        if not current_user.uploads:
            flash('Suspected hack attempt', 'danger')
            logout_user()
            return redirect(url_for('login'))

    # Remove all files in temporary directory
    for file in os.listdir(app.config['TEMP_FOLDER']):
        file_path = os.path.join(app.config['TEMP_FOLDER'], file)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            print(f'{file_path} deleted')
        except Exception as e:
            print(e)
    user_info = User.query.filter_by(username=username).first_or_404().serialize()
    return render_template('content/user.html', user=user_info, title=username)


@app.route('/logout')
@login_required
def logout():
    # Adding log out to the database
    add_log(current_user.id, "logout")

    logout_user()
    print("Logged out.")

    # Reset session variables
    session.clear()
    return redirect(url_for('index'))


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        edit_user_db(current_user.username, form.email.data, form.about_me.data)
        flash('Your changes have been saved.')

        # Adding log to the database
        add_log(current_user.id, 'edit_profile')
        return redirect(url_for('user', username=current_user.username))

    elif request.method == 'GET':
        form.email.data = current_user.email
        form.about_me.data = current_user.about_me

    return render_template('content/edit_profile.html', form=form, title='Edit Profile')


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Upload': Upload, 'Log': Log, 'User': User, 'UserBase': UserBase, 'encryptor': encryptor,
            'delete_all_users': delete_all_users}


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
            file_location = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id), filename)
            print(file_location)
            # If the folder doesn't exist, create it
            if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))):
                os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id)))

            key = UserBase.query.filter_by(id=current_user.id).first_or_404().generate_key()
            try:
                f.save(file_location)

                # Encrypting the file
                encryptor.encrypt_file(file_location, key)

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

    return render_template('content/upload_file.html', title='Upload')


@app.route('/download_file/<filename>', methods=['GET', 'POST'])
@login_required
def download_file(filename):
    filename = secure_filename(filename)
    filename_encrypted = filename + '.enc'
    key = UserBase.query.filter_by(id=current_user.id).first_or_404().generate_key()
    file_location = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id), filename_encrypted)
    try:
        # Copy the file to the temp folder
        shutil.copy(file_location, app.config['TEMP_FOLDER'])

        # Decrypt the file
        encryptor.decrypt_file(os.path.join(app.config['TEMP_FOLDER'], filename_encrypted), key)

        # Add the log to the database
        add_log(current_user.id, 'download_file')
        return send_from_directory(app.config['TEMP_FOLDER'], filename, as_attachment=True)

    except Exception as e:
        print(e)
        flash('Failed to download file')
        return redirect(url_for('content', username=current_user.username))


@app.route('/delete_file/<filename>', methods=['GET', 'POST'])
@login_required
def delete_file(filename):
    filename = secure_filename(filename)
    filename_encrypted = filename + '.enc'
    folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))

    if filename_encrypted in os.listdir(folder):
        # Delete the file from the database
        upload = Upload.query.filter_by(filename=filename, user_id=current_user.id).first_or_404()
        db.session.delete(upload)
        db.session.commit()
        # Delete the file from the upload folder
        os.remove(os.path.join(folder, filename_encrypted))
        # Increase num of deletes in the session
        session['num_deletes'] = session.get('num_deletes', 0) + 1
        flash('File deleted successfully.')

        # Adding log to the database
        add_log(current_user.id, 'delete_file')

    return redirect(url_for('user', username=current_user.username))


# The admin home page containing all users for admins
@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if current_user.type == 'admin':
        user_list = User.query.all()
        user_list = [user_.serialize() for user_ in user_list]
        for (user_print) in user_list:
            print(user_print)
        return render_template('admin/users.html', users=user_list, title='Users')

    return redirect(url_for('index'))


# The page containing activity of a content for admins
@app.route('/activity/<username>', methods=['GET', 'POST'])
@login_required
def activity(username):
    if current_user.type == 'admin':
        user_id = UserBase.query.filter_by(username=username).first_or_404().id

        log_list = Log.query.filter_by(user_id=user_id).all()
        log_list.reverse()
        log_list = [log.serialize() for log in log_list]
        print(log_list)

        return render_template('admin/activity.html', logs=log_list, title='Activity of ' + username)

    return redirect(url_for('index'))


# Edit content details for admins
@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    if current_user.type == 'admin':
        form = EditUserForm()
        if form.validate_on_submit():
            try:
                edit_user_db(username, form.email.data, form.about_me.data)
                flash('Your changes have been saved.')
                add_log(current_user.id, 'edit_user')
            except Exception as e:
                print(e)
                add_log(current_user.id, 'edit_user_failed')
                return redirect(url_for('edit_user', username=username))

            return redirect(url_for('users'))

        elif request.method == 'GET':
            form.email.data = UserBase.query.filter_by(username=username).first_or_404().email
            form.about_me.data = UserBase.query.filter_by(username=username).first_or_404().about_me
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
        return render_template('admin/all_logs.html', logs=log_list, title='All Logs')

    return redirect(url_for('index'))


@app.route('/delete_user/<username>', methods=['GET', 'POST'])
@login_required
def delete_user(username):
    if current_user.type == 'admin':
        try:
            delete_user_db(username)
            flash('User deleted successfully.')
            # adding log to the database
            add_log(current_user.id, 'delete_user')
            return redirect(url_for('users'))
        except Exception as e:
            flash('Error deleting content.')
            print(e)
    return redirect(url_for('index'))


@app.route('/verify_user/<user_id>', methods=['GET', 'POST'])
@login_required
def verify_user(user_id):
    if current_user.type == 'admin':
        try:
            verify_user_db(user_id)
            flash('User verified successfully.')
            # adding log to the database
            add_log(current_user.id, 'verify_user')
            return redirect(url_for('users'))
        except Exception as e:
            flash('Error verifying user.')
            print(e)
    return redirect(url_for('index'))


@app.route('/block_user/<user_id>', methods=['GET', 'POST'])
@login_required
def block_user(user_id):
    if current_user.type == 'admin':
        try:
            block_user_db(user_id)
            flash('User blocked successfully.')
            # adding log to the database
            add_log(current_user.id, 'block_user')
            return redirect(url_for('users'))
        except Exception as e:
            flash('Error blocking user.')
            print(e)
    return redirect(url_for('index'))


def share_file(filename, username):
    to_user_id = UserBase.query.filter_by(username=username).first_or_404().id
    filename_enc = filename + '.enc'

    decrypt_key = current_user.generate_key()
    encrypt_key = UserBase.query.filter_by(username=username).first_or_404().generate_key()

    # Decrypt the file
    from_filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    to_filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(to_user_id))

    # Copy the file to the user's folder
    shutil.copy(os.path.join(from_filepath, filename_enc), os.path.join(to_filepath))

    encryptor.decrypt_file(os.path.join(to_filepath, filename_enc), decrypt_key)

    # Encrypt the file
    encryptor.encrypt_file(os.path.join(to_filepath, filename), encrypt_key)

    # Add the upload to the database
    add_upload(to_user_id, filename, size=os.path.getsize(os.path.join(to_filepath, filename_enc)))

    # Add the log to the database
    add_log(current_user.id, 'share_file')
    return redirect(url_for('index'))


@app.route('/share_file_form', methods=['GET', 'POST'])
@login_required
def share_file_form():
    form = ShareFileForm()
    if form.validate_on_submit():
        try:
            share_file(form.filename.data, form.username.data)
            flash('File shared successfully.')
            return redirect(url_for('index'))
        except Exception as e:
            flash('Error sharing file.')
            print(e)

    return render_template('content/share_file_form.html', form=form, title='Share File')


def edit_upload(user_id, current_filename, new_filename):
    upload = Upload.query.filter_by(user_id=user_id, filename=current_filename).first_or_404()
    upload.filename = new_filename
    db.session.commit()


def rename_file(current_filename, new_filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    current_filename_enc = current_filename + '.enc'
    new_filename_enc = new_filename + '.enc'

    os.rename(os.path.join(filepath, current_filename_enc), os.path.join(filepath, new_filename_enc))

    # Edit the upload in the database
    edit_upload(current_user.id, current_filename, new_filename)

    # Add the log to the database
    add_log(current_user.id, 'rename_file')

    session['num_renames'] = session.get('num_renames', 0) + 1


@app.route('/rename_file_form', methods=['GET', 'POST'])
@login_required
def rename_file_form():
    form = RenameFileForm()
    if form.validate_on_submit():
        try:
            rename_file(form.current_filename.data, form.new_filename.data)
            flash('File renamed successfully.')
            return redirect(url_for('index'))
        except Exception as e:
            flash('Error renaming file.')
            print(e)

    return render_template('content/rename_file_form.html', form=form, title='Rename File')


def verify_session():
    """
    Checks if the user behaviour is suspicious.
    """
    if session.get('num_deletes') >= session.get('num_uploads'):
        return False
    if session.get('num_renames') >= session.get('num_uploads'):
        return False
    return True
