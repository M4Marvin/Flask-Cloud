import os
import shutil

from flask import render_template, url_for, redirect, send_from_directory, session
from flask_login import logout_user, login_required
from werkzeug.utils import secure_filename

from Application import encryptor
from Application.database import *
from Application.forms import *


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


@app.route('/user/<username>')
@login_required
def user(username):
    # Verify user session
    if not current_user.username == username and not current_user.type == 'admin':
        if not verify_session():
            # Block user if session is invalid
            block_user_db(current_user.id)
            logout_user()
            return redirect(url_for('auth.login'))
    # Block the user if he deleted all files
    if current_user.type == 'user':
        if not current_user.uploads:
            flash('Suspected hack attempt', 'danger')
            logout_user()
            return redirect(url_for('auth.login'))

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
        print(f'Number of deletes: {session["num_deletes"]}')
        flash('File deleted successfully.')

        # Adding log to the database
        add_log(current_user.id, 'delete_file')

    return redirect(url_for('user', username=current_user.username))


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
    print(f'{session.get("num_renames", 0)}')
    print(f'{session.get("num_deletes", 0)}')
    if session.get('num_deletes') >= session.get('num_uploads'):
        return False
    if session.get('num_renames') >= session.get('num_uploads'):
        return False
    return True
