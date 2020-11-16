from flask import(
    Blueprint, flash, redirect, render_template, request,url_for
)

from flask import session

from werkzeug.exceptions import abort

from . auth import login_required
from . db import get_db
from . security_utility_funcs import find_username_hash_from_id, find_user_from_uname, find_user_institution_id
bp = Blueprint("ticket_viewer", __name__)

# Combo box options. Used globally within the context of the ticket_viewer
# python file.
ticket_priority_options = ["low", "medium", "high"]
ticket_status_options = ["open", "resolved", "closed"]
ticket_type_options = ["development", "testing", "production"]

@bp.route('/ticket_viewer/<project_name>', methods=("GET", "POST"))
@login_required
def ticket_index(project_name : str):
    """ Provides an overview of the current tickets within a project. """
    db = get_db()

    project_id = db.execute("SELECT ProjectID FROM Project WHERE ProjectName = ?", 
        (project_name,)
    ).fetchone()["ProjectID"]

    project_tickets = db.execute(
        """SELECT TicketName, TicketType,  
        TicketTimestamp, BugDescription, TicketStatus, Priority
        FROM Ticket WHERE ProjectID = ?""", (project_id,)
    ).fetchall()

    # Indicate the project the user is currently interacting with.
    session["project_id"] = project_id
    
    return render_template("ticket_viewer/ticket_index.html", 
    project_name=project_name, project_tickets=project_tickets)

@bp.route('/ticket_viewer/<project_name>/view_ticket/<ticket_name>', methods=("GET", "POST"))
@login_required
def view_ticket(project_name : str, ticket_name : str):
    """ Provides an overview of a selected ticket. """
    db = get_db()

    selected_ticket = db.execute(
    """SELECT TicketID, TicketName, CreatorUsername, AssignedUsername, 
    TicketType, TicketTimestamp, BugDescription, TicketStatus, Priority
    FROM Ticket WHERE TicketName = ?""", (ticket_name,)
    ).fetchone()
    creator_username=selected_ticket["CreatorUsername"]
    user_assigned_username=selected_ticket["AssignedUsername"]
    # add a comment
    if request.method == "POST":
        ticket_status = selected_ticket["TicketStatus"]
        from . security_utility_funcs import gen_ID as gen_comment_id
        if ticket_status != "closed":
        
            comment_id = gen_comment_id()
            user_commentor_id = session["user_id"]
            commentor_username = session["username"]
            ticket_id = selected_ticket["TicketID"]
            comment_title=request.form["comment_title"]
            comment_text = request.form["ticket_comment"]

            error = None

            if comment_title.strip() is None:
                error = "Ticket comment must have a title"
                flash(error)

            if comment_text.strip() is None:
                error = "Can't submit a blank comment"
                flash(error)

            if error is not None:
                flash(error)
            else:
                db.execute(
                    """ INSERT INTO TicketComment (CommentID, 
                    UserCommentorID, CommenterUsername, TicketID, 
                    CommentTitle, CommentText)
                    VALUES (?, ?, ?, ?, ?, ?) """, 
                    (comment_id, user_commentor_id, commentor_username, 
                    ticket_id, comment_title, comment_text)
                )
                db.commit()
        else:
            error = "Can't comment on a closed ticket!"
            flash(error)

    # display comments
    ticket_comments = db.execute(
        """SELECT CommenterUsername, CommentTitle, CommentText,
        CommentTimestamp FROM TicketComment WHERE TicketID = ?  ORDER BY CommentTimestamp""", (selected_ticket["TicketID"],)
    ).fetchall()
    

    return render_template("ticket_viewer/view_ticket.html", 
    selected_ticket=selected_ticket, ticket_comments=ticket_comments, 
    project_name=project_name, creator_username=creator_username,
    user_assigned_username=user_assigned_username)

@bp.route("/ticket_viewer/<project_name>/create_ticket", methods=("GET", "POST"))
@login_required
def create_ticket(project_name : str):
    if request.method == "POST":
        from . security_utility_funcs import gen_ID as gen_ticket_id
        ticket_id = gen_ticket_id()
        ticket_name = request.form["ticket_name"]
        ticket_type = request.form.get("ticket_type")
        ticket_status = request.form.get("ticket_status")
        user_assigned_uname = request.form["user_assigned_uname"]
        bug_description = request.form["bug_description"]
        priority = request.form.get("priority")
        error = None

        # data entry checkers.
        user_assigned_id = find_user_from_uname(user_assigned_uname)

        if not ticket_name:
            error = "A ticket title is required."
        
        if not ticket_type:
            error = "A ticket description is required."
        
        if not ticket_status:
            error = "A ticket status is required."
        
        if not user_assigned_uname:
            error = "A user must be assigned to the ticket."

        if not bug_description:
            error = "A description of the ticket bug is required."

        if not priority:
            error = "A ticket priority level is required."
        
        if user_assigned_id is None:
            error = "Could not find a user to assign with the username: {}".format(user_assigned_uname,)
        
        users_in_different_institutions = session["institution_id"] != find_user_institution_id(user_assigned_id)
        if users_in_different_institutions:
            error = "Can't assign a ticket to a user not within the same institution"
        
        if error is not None:
            flash(error)
        
        else:
            db = get_db()
            db.execute(
                """
                INSERT INTO Ticket (TicketID, TicketName, ProjectID, UserCreatorID, 
                CreatorUsername, UserAssignedToID, AssignedUsername, 
                TicketType, BugDescription, TicketStatus, Priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (ticket_id, ticket_name, session["project_id"], 
                session["user_id"], session["username"],user_assigned_id, 
                user_assigned_uname, ticket_type,
                bug_description, ticket_status, priority
                )
            )
            db.commit()

            # Get project tickets for display within the ticket index.
            project_tickets = db.execute(
                """
                SELECT TicketID, TicketName, ProjectID, UserCreatorID, UserAssignedToID,
                TicketType, TicketTimestamp, BugDescription, TicketStatus,
                Priority FROM Ticket WHERE ProjectID = ?
                """, (session["project_id"],)).fetchall()

            return redirect(url_for("ticket_viewer.ticket_index", project_name=project_name, project_tickets=project_tickets))
        
    return render_template("ticket_viewer/create_ticket.html",
    ticket_type_options=ticket_type_options,
    ticket_priority_options=ticket_priority_options, 
    ticket_status_options=ticket_status_options, 
    project_name=project_name)