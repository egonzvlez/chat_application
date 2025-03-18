from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import random
from string import ascii_uppercase

app = Flask(__name__)
app.config["SECRET_KEY"] = "random_key"
socketio = SocketIO(app)

 # Dictionary to store active rooms
rooms = {}

def generate_code(length):
    # generates room code at size 'length' and makes sure that code doesn't exist already
    while True:
        code =""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        # checks to see if code is in dictionary
        if code not in rooms:
            break

    return code

# Route for homepage
@app.route("/", methods=["POST", "GET"])
def home():
    # clear existing session data
    session.clear()
    # handle for submissions
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        # makes ure thet entered a name
        if not name:
            return render_template("home.html", error="Please enter a name.", code=code, name=name)

        # if joining a room, makes sure they provide a room code
        if join != False and not code:
            return render_template("home.html", error="Please enter a room code.", code=code, name=name)
        
        room = code

        # creates a new room
        if create != False:
            room = generate_code(4)
            rooms[room] = {"members": 0, "messages": []}
        elif code not in rooms:
            return render_template("home.html", error="Room does not exist.", code=code, name=name)
        
        # store info in session and redirects to room
        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    # just shows the home page for GET request
    return render_template("home.html")


# route for the chat room page
@app.route("/room")
def room():
    return render_template("room.html")

if __name__ == "__main__":
    socketio.run(app,debug=True)