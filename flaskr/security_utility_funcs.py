import os
from struct import unpack
from sys import byteorder

from werkzeug.security import generate_password_hash as wzg_encrypt
from werkzeug.security import check_password_hash as wzg_check_hashes

from re import findall as mac_address_formatter

from uuid import getnode as get_mac

from . db import get_db

encryption_method = "pbkdf2:sha256:"
additional_hash_prepend_string = "150000$"

def gen_ID():
    """
     Produces 'truely' random ids/numbers,
     (not based on software state, and not reproducible).
     Attackers can't predict random numbers 
     generated based on software state +
     can't base finding data on sequential IDs.
    """
    bytes_for_id = 4
    # byteorder represents the host systems native byteorder.
    
    # here we use 4 bytes for the ID value which is within the bounds of the 
    # SQL INTEGER type.
    true_random_id = int.from_bytes(os.urandom(bytes_for_id), byteorder)
    return true_random_id

def encrypt_data(data : str):
    """
    Extension of werkzeugs generate_password_hash function.
    Used to remove hashing algorithm details from encrypted data
    before being stored in the application database.
    
    Werkzeug generate_password_hash function uses
    sha256 encryption and applies a 8 letter length salt by default.
    see under security helpers:
    https://werkzeug.palletsprojects.com/en/0.15.x/utils/
    """
    encrypted_data = wzg_encrypt(data)

    # Remove the hash method prepend detailing the hashing algorithm used
    # for store of data hash. Leaving in would make the hash insecure!
    hash_method_prepend = encryption_method + additional_hash_prepend_string

    encrypted_data = encrypted_data.replace(hash_method_prepend, "")
    return encrypted_data


def check_hashes(retrieved_hash : str, input : str):
    """
    Used to reapply hashing algorithm string prepend to encrypted data.
    This allows werkzeugs check_password_hash function to accurately compare input provided
    with relevant hashed data within the application database.
    """
    retrieved_hash = encryption_method + additional_hash_prepend_string + retrieved_hash
    hash_match = wzg_check_hashes(retrieved_hash, input)
    return hash_match

def find_username_hash_from_id(user_id : int):
    """ Given a user ID, retrieve a username hash within the database """
    db = get_db()

    uname_hash_get = db.execute(
        "FROM User SELECT UserName WHERE UserID = ?", (user_id)
    ).fetchone()

    return uname_hash_get["UserName"]

def find_user_from_uname(user_name : str):
    """ Given a username, retireve a user ID within the database """
    db = get_db()

    user_rows = db.execute(
        "SELECT UserName, UserID FROM User "
    ).fetchall()

    user_id = None
    if user_rows is not None:
        for user_row in user_rows:
            hash_match = check_hashes(user_row["UserName"], user_name)
            if hash_match:
                user_id = user_row["UserID"]
                break

    return user_id

def find_user_institution_id(user_id : int):
    """ Given a user ID, retrieve a users institution ID within
    the database. """
    db = get_db()

    user_row = db.execute(
        "SELECT InstitutionID FROM User WHERE UserID = ?", (user_id,)
    ).fetchone()

    if user_row == None:
        return None

    return user_row["InstitutionID"]

def get_user_mac_address():
    """ Used to log the user mac address for two factor authentication """
    mac_address_pattern = ".."
    mac_address_format_char = "%012x"
    splitter = ":"
    # two factor authentication to stop unauthorised access
    # through session hijacking.
    mac_address = splitter.join(mac_address_formatter(mac_address_pattern,
        mac_address_format_char % get_mac()))

    return mac_address