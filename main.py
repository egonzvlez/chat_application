from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import random
from string import ascii_uppercase

app = Flask(__name__)
app.config["SECRET_KEY"] = "random_key"
socketio = SocketIO(app)

rooms = {}

def generate_code(length):
    while True:
        code =""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        # checks to see if code is in dictionary
        if code not in rooms:
            break

    return code

@app.route("/", methods=["POST", "GET"])
def home():
    session.clear()

    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        # Check if user passed a name (empty/blank)
        if not name:
            return render_template("home.html", error ="Enter a name, please.", code=code, name=name)
        
        # Attempting to join a room
        if join != False and not code:
            return render_template("home.html", error ="Enter a room code, please.", code=code, name=name)
        
        # room generation
        room = code
        if create != False:
            room = generate_code(4)
            rooms[room] = {"members": 0, "messages": []}
            # they must be trying to join a room
        elif code not in rooms:
            return render_template("home.html", error ="The room doesn't exist.", code=code, name=name)
        
        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("home.html")

app.route("/room")
def room():
    return render_template("room.html")

if __name__ == "__main__":
    socketio.run(app,debug=True)