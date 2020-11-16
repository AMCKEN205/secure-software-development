import sqlite3
import click
from flask import current_app as cur_app
from flask import g as app_context
from flask.cli import with_appcontext


"""
***g/db_access object***
g is a an object unique to each request.
Used to store data that may be accessed by
multiple functions during a request.
connection stored and reused if get_db
called multiple times.
"""

"""
**current_access object***
object used to point to the flask application handling
the request. get_db called when the application has
been created and handling the request. 
"""

def get_db():
    if "db" not in app_context:
        # set db connection for request
        app_context.db = sqlite3.connect(
            cur_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        app_context.db.row_factory = sqlite3.Row
    return app_context.db

def close_db(e=None):
    """ Close database connection when no longer
    required. Also stops the stacktrace being revealed
    in the event of server-side database access error. """
    db = app_context.pop("db", None)
    # TODO: Log errors
    if db is not None:
        db.close()

def init_db():
    db = get_db()

    with cur_app.open_resource("schema.sql") as db_f:
        db.executescript(db_f.read().decode("utf8"))

@click.command("init-db")
@with_appcontext
def init_db_command():
    """ Clear existing data and generate new tables """
    init_db()
    click.echo("database initalized.")

def init_app(app):
    """ Setup required server-side db functionality. """
    # Close the database connection with the user on session end.
    app.teardown_appcontext(close_db)
    # Add database initalisation command to flask.
    app.cli.add_command(init_db_command)

