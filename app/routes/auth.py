import logging

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    current_app,
    session,
    g,
)

from flask import Flask, redirect, url_for, session, request, jsonify
from flask_session import Session

from flask_login import login_user, logout_user, current_user
from flask_principal import identity_changed, Identity, AnonymousIdentity, Permission, RoleNeed

from app.models import db, User

from uuid import uuid4
import bcrypt

import identity.web
import requests
import app.env_vars as env_vars
from werkzeug.middleware.proxy_fix import ProxyFix

from app.routes.utils import email_validator
from app.routes.utils import ErrorDuringHTMLRoute, wrap_exceptions_as

logger = logging.getLogger(__name__)
auth_ = Blueprint("auth_", __name__, template_folder="templates")
__version__ = "0.8.0"  # The version of this sample, for troubleshooting purpose

def oauth_setup(app):
    app.config.from_object(env_vars)
    assert app.config["REDIRECT_PATH"] != "/", "REDIRECT_PATH must not be /"
    Session(app)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    app.jinja_env.globals.update(Auth=identity.web.Auth)  # Useful in template for B2C
    app.auth = identity.web.Auth(
        session=session,
        authority=app.config["AUTHORITY"],
        client_id=app.config["CLIENT_ID"],
        client_credential=app.config["CLIENT_SECRET"],
    )

# a role mentioned in permission means it has access there
admin_permission = Permission(RoleNeed("admin"))
edit_permission = Permission(RoleNeed("admin"), RoleNeed("editor"))
member_permission = Permission(RoleNeed("admin"), RoleNeed("editor"), RoleNeed("member"))


def public_route(func):
    """Decorator to mark a route as accessible by non-logged-in users"""
    func.is_public = True
    return func

def disabled_in_kiosk(func):
    """Decorator to make a route wholly inaccessible in kiosk-mode"""
    func.disabled_in_kiosk = True
    return func


@auth_.route("/login", methods=["GET"])
@disabled_in_kiosk
@public_route
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def login():
    return render_template("login.html", version=__version__, **current_app.auth.log_in(
        scopes=current_app.config["SCOPE"], # Have user consent to scopes during log-in
        redirect_uri=url_for("auth_.auth_response", _external=True), # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
        prompt="select_account",  # Optional. More values defined in  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        ))
    """Returns login page (HTML response)"""
    g.route_title = "Login Page"

    if current_user.is_authenticated:
        logger.info("user already logged-in, sending them home")
        return redirect("/")

    else:
        logger.info("serving page")
        return render_template("login.html")


@auth_.route(env_vars.REDIRECT_PATH)
@public_route
def auth_response():
    result = current_app.auth.complete_log_in(request.args)
    email = result['preferred_username']
    
    user = User.query.filter_by(email=email).first()
    user.session_token = str(uuid4())
    
    if "error" in result:
        return render_template("auth_error.html", result=result)
    
    try:
        logger.debug(f"attempting to set {email}'s session token on DB")
        db.session.commit()
        logger.info(f"successfully set {email}'s session token on DB")

        # Tell Flask-Principal the identity changed
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

        login_user(user)
        logger.info(f"login successful ({email})")
        return redirect(url_for("question_.home"))

    except Exception:
        db.session.rollback()
        flash("Failed to log you in / set session token.")
        logger.exception(f"failed to set {email}'s session token on DB (failed to log them in)")
        return redirect(url_for("auth_.login"))


@auth_.route("/call_downstream_api")
def call_downstream_api():
    token = current_app.auth.get_token_for_user(env_vars.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    # Use access token to call downstream api
    api_result = requests.get(
        env_vars.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    return render_template('display.html', result=api_result)


@auth_.route("/login", methods=["POST"])
@disabled_in_kiosk
@public_route
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def login_post():
    """Processes login attempt and redirects user based on success

    pass -> to Decider home
    fail -> back to login page
    """
    g.route_title = "Login Request"

    email = request.form.get("email", "").lower()
    password = request.form.get("password", "")

    # catch emails/passwords that aren't even usable on the platform
    if not email_validator(email):
        flash("The email provided isn't valid.")
        logger.info("login attempt used an invalid email address")
        return redirect(url_for("auth_.login"))

    # catch passwords longer than allowed on platform (limit picked as bcrypt has a limit a bit higher)
    if len(password) > 48:
        flash("The password provided isn't valid.")
        logger.info(f"login attempt ({email}) used an invalid password")
        return redirect(url_for("auth_.login"))

    # no user with this email
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No user exists for this email.")
        logger.info(f"login attempt used an email ({email}) not corresponding to any user")
        return redirect(url_for("auth_.login"))

    # wrong pass used
    if not bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
        flash("Incorrect password.")
        logger.info(f"login failed ({email}) - due to incorrect password")
        return redirect(url_for("auth_.login"))

    user.session_token = str(uuid4())

    try:
        logger.debug(f"attempting to set {email}'s session token on DB")
        db.session.commit()
        logger.info(f"successfully set {email}'s session token on DB")

        # Tell Flask-Principal the identity changed
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

        login_user(user)
        logger.info(f"login successful ({email})")
        return redirect(url_for("question_.home"))

    except Exception:
        db.session.rollback()
        flash("Failed to log you in / set session token.")
        logger.exception(f"failed to set {email}'s session token on DB (failed to log them in)")
        return redirect(url_for("auth_.login"))


@auth_.route("/logout", methods=["GET"])
@disabled_in_kiosk
@wrap_exceptions_as(ErrorDuringHTMLRoute)
def logout():
    """Logs-out the requesting user and redirects them to the login page"""
    g.route_title = "Logout Page"

    user_email = current_user.email

    logout_user()  # pops user.get_id() (session_token) from session so it cannot be used anymore

    # Remove session keys set by Flask-Principal
    for key in ("identity.name", "identity.auth_type"):
        session.pop(key, None)
    logger.debug(f"session keys removed ({user_email})")

    # Tell Flask-Principal the user is anonymous
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    logger.info(f"logged out ({user_email})")
    return redirect(url_for("auth_.login"))