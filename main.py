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

        # makes sure thet entered a name
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
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))
    
    return render_template("room.html", code=room, messages=rooms[room]["messages"])

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    content = {
        "name": session.get("name"),
        "message": data["data"]
    }

    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    send({"name": name, "message": "has left the room"}, to=room)
    print(f"{name} has left the room {room}")




if __name__ == "__main__":
    socketio.run(app,debug=True)