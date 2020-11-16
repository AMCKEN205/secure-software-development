import os 
from flask import Flask as fk
from flask import redirect

# import database interfacing python code.
from . import db
from . import auth
from . security_utility_funcs import gen_ID as gen_secret_key
from . import project_viewer
from . import ticket_viewer

def create_app(test_config=None):
    # create and configure the app
    app = fk(__name__, instance_relative_config=True)
    # Set secret key through flask for asymmetric encryption 
    # between client and server.
    
    # Secret key never included in data sent to client.
    # Therefore client can't tamper with session data and produce a new signature.
    app.config.from_mapping(
        SECRET_KEY=str(gen_secret_key()),
        DATABASE=os.path.join(app.instance_path, "flaskr.sqlite"
        )
    )

    """
    app.config.from_pyfile() overrides flask default configuration values
    with values taken from the config.py file in the instance folder 
    if it exists. 
    """
    
    if test_config is None:
        # load the instance config, if it exists, when nto testing
        app.config.from_pyfile("config.py", silent=True)
    else: 
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists 
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    db.init_app(app)
    
    # setup blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(project_viewer.bp)
    app.register_blueprint(ticket_viewer.bp)
    app.add_url_rule("/", endpoint="project_viewer")
    return app


