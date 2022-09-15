from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from Application.admin import bp
from Application.admin.utils import get_logs_by_username, get_all_logs, verify_user, block_user
from Application.models import User


@bp.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    """
    This route is used to display all users in the database.
    :return: The users.html template with all users in the database.
    """
    if current_user.type == 'admin':
        user_list = User.query.all()
        user_list = [user_.serialize() for user_ in user_list]
        for (user_print) in user_list:
            print(user_print)
        return render_template('admin/users.html', users=user_list, title='Users')

    return redirect(url_for('index'))


@bp.route('/activity/<username>', methods=['GET', 'POST'])
@login_required
def activity(username):
    """
    This route display all  activity for a specific user.
    :param username: The username of the user to display activity for.
    :return: The activity.html template with all activity for the user.
    """
    if current_user.type == 'admin':
        try:
            log_list = get_logs_by_username(username)
            return render_template('admin/activity.html', logs=log_list, title='Activity')
        except ValueError:
            return redirect(url_for('admin.users'))

    return redirect(url_for('index'))


@bp.route('/all_activity', methods=['GET', 'POST'])
@login_required
def all_activity():
    """
    This route display all activity for all users.
    :return: The activity.html template with all activity for all users.
    """
    if current_user.type == 'admin':
        try:
            log_list = get_all_logs()
            return render_template('admin/activity.html', logs=log_list, title='Activity')
        except Exception as e:
            print(e)
            return redirect(url_for('admin.users'))

    return redirect(url_for('index'))


@bp.route('/verify/<user_id>', methods=['GET', 'POST'])
@login_required
def verify(user_id):
    """
    This route is used to verify a user.
    :param user_id: The id of the user to verify.
    :return: The users.html template with all users in the database.
    """
    if current_user.type == 'admin':
        try:
            verify_user(user_id)
            flash('User has been verified.', 'success')
        except Exception as e:
            print(e)
            flash('User could not be verified.', 'danger')

        return redirect(url_for('admin.users'))
    return redirect(url_for('index'))


@bp.route('/block/<user_id>', methods=['GET', 'POST'])
@login_required
def block(user_id):
    """
    This route is used to block a user.
    :param user_id: The id of the user to block.
    :return: The users.html template with all users in the database.
    """
    if current_user.type == 'admin':
        try:
            block_user(user_id)
            flash('User has been blocked.', 'success')
        except Exception as e:
            print(e)
            flash('User could not be blocked.', 'danger')

        return redirect(url_for('admin.users'))
    return redirect(url_for('index'))


