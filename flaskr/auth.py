import functools
import os
from flask import (
    Blueprint, flash, redirect, render_template, request,
    session, url_for
)
from flask import g as app_context

from flaskr.db import get_db

from . security_utility_funcs import gen_ID as gen_user_id

from . security_utility_funcs import encrypt_data, check_hashes

from . security_utility_funcs import get_user_mac_address as get_mac

from io import FileIO as file_reader

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.route('/register', methods=('GET', 'POST'))
def register():
    """ adds a new user to the users database """
    if request.method == "POST":
        # user credentials.
        username = request.form["username"]
        password = request.form["password"]
        # these credentials are used to check user validity
        # / right to access the system.
        institution = request.form["institution"]
        institutional_email = request.form["institutional_email"]
        full_name = request.form["full_name"]
        mac_address = get_mac()

        password_min_len = 8 #chars
        password_special_chars_required = ["!", "#", "$", "%", "&", "'", "(" ,")" ,
                                            "*", "+", ",", "-", ".", "/", ":", ";"
                                            ,"<" ,"=" ,">" ,"?" ,"@" ,"[" ,"\\" ,"]", 
                                            "^", "_", "`", "{", "|", "}", "~"]
        db = get_db()
        error = None

        uname_taken_query = "SELECT UserName FROM User"
        uname_column = "UserName"
        email_taken_query = "SELECT InstitutionalEmail FROM User"
        email_column = "InstitutionalEmail"
        if username is None:
            error = "Username cannot be blank."

        elif password is None:
            error = "password is cannot be blank."

        elif credential_taken_check(username, db, uname_taken_query, uname_column):
            error = "User {} is already registered.".format(username)
        
        elif not inst_valid(institution, db):
            error = "Institution {} is not a valid institution for registration".format(institution)
        
        elif email_domain_invalid(institutional_email, db, institution):
            error = "Email: {} does not contain a valid institutional email domain for given institution: {}".format(institutional_email, institution)

        elif credential_taken_check(institutional_email, db, email_taken_query, email_column):
            error = "Email {} is already tied to a user.".format(institutional_email) 
        
        common_pass_file_open_fail = False

        try:
            common_passes_file = "common_passwords.txt"
            common_passes_file_path = os.path.dirname(os.path.abspath(__file__))
        except:
            error = "Error whilst checking the commonality of the entered password"
            common_pass_file_open_fail = True
        
        # password validation

        if not common_pass_file_open_fail: 
            with open("{}/{}".format(common_passes_file_path, common_passes_file)) as c_p_f:
                try:
                    for pos, common_pass in enumerate(c_p_f):
                        # Remove the newlines present within the text file.
                        # In case we're on windows, handle carriage returns too!
                        if password == (
                            (common_pass.replace("\n", ""))
                                .replace("\r","")).replace("\r\n", ""):
                            error = """password chosen is too common, 
                            choose a more unique password!"""
                            break
                finally:
                        c_p_f.close()

        if len(password) < password_min_len:
            error ="""Password is too short, password should at least be
            8 characters long"""

        pass_contains_special_character = False

        # password should contain at least one special character.
        for char in password_special_chars_required:
            if char in password:
                pass_contains_special_character = True
                break
        
        if pass_contains_special_character == False:
            error = """Password must contain a special character,
            at least one of the following should be within the password:
            """
            for char in password_special_chars_required:
                error += "{} ".format(char)

        if mac_address is None:
            error = "Could not log user mac address"
        if error is None:
            # Add the user to the database.

            # User id made 'truely random' to ensure
            # ids aren't easily guessable.
            user_id = gen_user_id()

            # Data hashed where required to ensure unreadability
            # if stolen.
            uname_hash = encrypt_data(username)
            password_hash = encrypt_data(password)
            full_name_hash = encrypt_data(full_name)
            institutional_email_hash = encrypt_data(institutional_email)
            mac_address_hash = encrypt_data(mac_address)
            # Get the institution ID to associate with the
            # new user.
            institution_id_row_object = db.execute(
                "SELECT InstitutionID FROM Institution WHERE InstitutionName = ?", (institution,)
            ).fetchone()

            pos_of_id_in_row = 0
            institution_id = institution_id_row_object[pos_of_id_in_row]

            db.execute(
                """INSERT INTO 
                User (UserID, InstitutionID, InstitutionalEmail, 
                UserName, Password, FullName, MacAddress) 
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, institution_id, institutional_email_hash, 
                uname_hash, password_hash, full_name_hash, mac_address_hash)
            )
            db.commit()
            # Send to login page.
            return redirect(url_for("auth.login"))

        flash(error)
    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    """ logs in a user using provided username and password """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # returns an indication as to whether the login  was successful, 
        # the ids of the user and their institution if logged in, and an error message
        # if the login was unsuccessful.
        login_credentials_correct, user_id, inst_id, login_error = login_authenticate(username, password)

        if login_credentials_correct:
            session.clear()
            # User ID linked to logged in session to easily 
            # identify the user within the database.
            session["user_id"] = user_id
            session["username"] = username
            session["institution_id"] = inst_id
            session["MacAddress"] = get_mac()

            return redirect(url_for('project_viewer.project_index'))
        else:
            flash(login_error)

    return render_template("auth/login.html")

# runs before view function
@bp.before_app_request
def load_logged_in_user():
    """ Used to identify users between application views. """

    user_id = session.get("user_id")

    if user_id is None:
        app_context.user = None
    else:
        app_context.user = get_db().execute(
            "SELECT * FROM user WHERE UserID = ?", (user_id,)
        ).fetchone()

@bp.route("/logout")
def logout():
    """ Logs the user out and clears the session """
    session.clear()
    # send to index page
    return redirect(url_for("auth.login"))  

def login_required(view):
    """ Validates a user is logged in before performing an action requiring login """

    @functools.wraps(view)

    def wrapped_view(**kwargs):
        user_logged_in = app_context.user is not None
        mac_addr_match = False

        # Not logged in means we already know to send user back to login.
        # No user id in session so would also gen stack trace.
        if user_logged_in:
            db = get_db()

            db_column_mac_addr = "MacAddress"

            query = "Select {} FROM User WHERE UserID = ?".format(db_column_mac_addr)

            mac_addr_hash = db.execute(query, (session["user_id"],)).fetchone()["MacAddress"]
            
            if mac_addr_hash is not None:
                mac_addr_match = check_hashes(mac_addr_hash, session["MacAddress"])

        if user_logged_in == False or mac_addr_match == False:
            # send back to login page
            return redirect(url_for("auth.login"))
        
        # continue loading view
        return view(**kwargs)
    
    return wrapped_view

""" utility functions """

def credential_taken_check(input_data : str, db : app_context, query : str, db_column:str):
    """ check if a given credential entered is already in use """
    db_rows = db.execute(query)
    cred_taken = False
    for db_row in db_rows:
        hash_match = check_hashes(db_row[db_column], input_data)
        if hash_match:
            cred_taken = True
            break

    return cred_taken

def login_authenticate(username : str, password : str):
    """ check the username and password combo entered are tied to the same user.
    ID of the users is returned on login credential check success. """
    
    # Authenticate the users right to access against the users mac address
    mac_addr = get_mac()

    # Set the database connection
    db = get_db()

    # Indicate whether the username + password combo entered is tied to the same user.
    user_authentication_state = False

    # Set the column names for the username and password hashes, and the user ID.
    db_column_uname = "UserName"
    db_column_pass = "Password"
    db_column_uid = "UserId"
    db_column_inst_id = "InstitutionID"
    db_column_mac_addr = "MacAddress"
    # The password hash, user ID and institution ID retrieved form the database.
    pass_hash = None
    user_id = None
    inst_id = None
    mac_addr_hash = None
    # The error message to be shown to the user on login failure.
    login_error = None

    query = "Select {}, {}, {}, {}, {} FROM User".format(db_column_uid, 
            db_column_inst_id, db_column_uname, db_column_pass, db_column_mac_addr)

    db_rows = db.execute(query)

    # Find the username entered within the database rows retrieved
    for db_row in db_rows:
        uname_match = check_hashes(db_row[db_column_uname], username)
        if uname_match:
            pass_hash = db_row[db_column_pass]
            user_id = db_row[db_column_uid]
            inst_id = db_row[db_column_inst_id]
            mac_addr_hash = db_row[db_column_mac_addr]
            break
    
    # Username provided doesn't match a username in the database.
    if pass_hash is None:
        login_error = "Incorrect username."
    # User mac address couldn't be found, unable to two factor authenticate.
    elif mac_addr_hash is None:
        login_error = "Could not accurately authenticate device."
    else:
        pass_match = check_hashes(pass_hash, password)
        mac_addr_match = check_hashes(mac_addr_hash, mac_addr)
        if pass_match and mac_addr_match:
            user_authentication_state = True
        elif pass_match == False:
            login_error = "Incorrect password."
        elif mac_addr_match == False:
            login_error = "Device not authenticated."
    return user_authentication_state, user_id, inst_id, login_error

def inst_valid(inst : str, db : app_context):
    """ check instituion entered exists within the database """
    institution_valid = db.execute(
        "SELECT InstitutionID FROM Institution WHERE InstitutionName = ?", (inst,)
    ).fetchone() is not None
    return institution_valid

def email_domain_invalid(email : str, db : app_context, entered_institution : str):
    """ Check if the email entered is a vaild institutional
    email domain. """
    domain_invalid = False

    email_domain_position = 1
    split_char = "@"

    # Incorrect format
    if split_char not in email:
        domain_invalid = True
        return domain_invalid
    email_domain = email.split(split_char)[email_domain_position]
    institution_name_column = "InstitutionName"

    # Check against paypal emails for convenience. A deployed 
    # app would likely have a specific email domain db entry + 
    # Would likely authorise entered email against company servers.
    
    linked_instituition = db.execute(
        "SELECT InstitutionName FROM Institution WHERE instr(PayPalEmail, ?)", (email_domain,)
    ).fetchone()
    
    
    if linked_instituition is None:
        domain_invalid = True
 
    elif linked_instituition[institution_name_column] != entered_institution:
        domain_invalid = True
    
    return domain_invalid
