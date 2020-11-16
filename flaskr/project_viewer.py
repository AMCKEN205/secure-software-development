from flask import(
    Blueprint, flash, redirect, render_template, request,url_for
)

from flask import session

from werkzeug.exceptions import abort

from . auth import login_required
from . db import get_db
from . security_utility_funcs import gen_ID as gen_ticket_id

bp = Blueprint("project_viewer", __name__)

@bp.route('/', methods=("GET", "POST"))
@login_required
def project_index():
    """ Provides an overview of the current projects within
    a institution. """
    db = get_db()
    projects = db.execute(
        """SELECT ProjectName, ProjectDescription, ProjectCreationTimestamp
        FROM Project WHERE InstitutionID = ?""", 
        (session["institution_id"],)
    ).fetchall()


    return render_template("project_viewer/project_index.html", projects=projects)

@bp.route("/create_project", methods=("GET", "POST"))
@login_required
def create_project():
    if request.method == "POST":
        project_id = str(gen_ticket_id())
        project_name = request.form["project_name"]
        project_description = request.form["project_description"]
        error = None

        if not project_name:
            error = "A project title is required."
        
        if not project_description:
            error = "A project description is required."

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                """
                INSERT INTO Project (ProjectID, 
                InstitutionID, ProjectName, ProjectDescription)
                VALUES (?, ?, ?, ?)
                """, (project_id, str(session["institution_id"]), project_name,
                    project_description)
            )
            db.commit()
            return redirect(url_for("project_viewer"))
        
    return render_template("project_viewer/create_project.html")

