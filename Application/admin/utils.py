from Application import db
from Application.models import Log, User


def get_logs(user_id):
    """
    This function is used to get all logs for a specific user in list form.
    :param user_id: The id of the user to get logs for.
    :return: A list of logs for the user.
    """
    log_list = Log.query.filter_by(user_id=user_id).all()
    log_list = [log_.serialize() for log_ in log_list]
    return log_list


def get_logs_by_username(username):
    """
    This function is used to get all logs for a specific user in list form.
    :param username: The username of the user to get logs for.
    :return: A list of logs for the user.
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        raise ValueError('User does not exist.')
    return get_logs(user.id)


def get_all_logs():
    """
    This function is used to get all logs for all users in list form.
    :return: A list of logs for all users.
    """
    log_list = Log.query.all()
    log_list = [log_.serialize() for log_ in log_list]
    return log_list


def verify_user(user_id):
    """
    This function is used to verify a user.
    :param user_id: The id of the user to verify.
    :return: None
    """
    user = User.query.get(int(user_id))
    user.verified = True
    db.session.commit()


def block_user(user_id):
    """
    This function is used to block a user.
    :param user_id: The id of the user to block.
    :return: None
    """
    user = User.query.get(int(user_id))
    user.verified = False
    db.session.commit()
