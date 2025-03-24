from flask import Flask, render_template, request, session, redirect, url_for, send_file, jsonify
from flask_socketio import join_room, leave_room, send, SocketIO
from werkzeug.utils import secure_filename
from string import ascii_uppercase
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from model import db, User, DirectMessage, Room, RoomMessage, SharedFile
from time import time
from collections import defaultdict
from sqlalchemy import or_, and_
from chat_logger import ChatLogger
import base64
import os
import random


app = Flask(__name__)
app.config["SECRET_KEY"] = "random_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File upload settings
app.config["UPLOAD_FOLDER"] = "uploaded_files"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB 
app.config["ALLOWED_EXTENSIONS"] = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip"}

# Create upload folder if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

socketio = SocketIO(
    app,
    ping_timeout=25,
    ping_interval=10
)

# Rate limiting 
RATE_LIMIT = {
    "MAX_MESSAGES": 5,      # max messages in a window
    "TIME_WINDOW": 10,  
    "COOLDOWN": 15         
}

# Initialize db
db.init_app(app)
migrate = Migrate(app,db)

with app.app_context():
    db.create_all()

# Keeps track of message per user
message_history = defaultdict(list)
user_cooldowns = {}

# Initialize the chat logger after the app config
chat_logger = ChatLogger()

# Dictionary to keep track of active session log files
active_log_sessions = {}


def generate_code(length):
    # Generates room code at size 'length' and makes sure that code doesn't exist already
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        # Check if code exists in the database
        if not Room.query.filter_by(code=code).first():
            break

    return code

def cleanup_inactive_log_sessions():
    inactive_sessions = []
    
    for session_key, log_path in active_log_sessions.items():
        # Checks if the session is for a room
        if session_key.startswith("room_"):
            room_code = session_key[5:]  # Remove "room_" prefix
            room = Room.query.filter_by(code=room_code).first()
            
            # If room doesn't exist or has no members, end the session
            if not room or room.members_count == 0:
                chat_logger.end_session(log_path)
                inactive_sessions.append(session_key)
    
    # Removes inactive sessions
    for session_key in inactive_sessions:
        active_log_sessions.pop(session_key, None)

user_last_active = {}

def update_active_timestamp(session_key):
    """Update the timestamp for when a session was last active."""
    user_last_active[session_key] = datetime.utcnow()


@app.route("/", methods=["POST", "GET"])
def home():
    # Check if user is logged in
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    # Get username from session
    username = session.get("username")
    if not username:
        session.clear()
        return redirect(url_for("login"))
            
    # Handle room creation/joining
    if request.method == "POST":
        # ***debug*** - print form data to see what's being submitted
        print("Form data:", request.form)
        
        create_btn = "create" in request.form
        code = request.form.get("code", "")
        
        # creates a new room
        if create_btn:
            try:
                room_code = generate_code(4)
                # Create a new room in the database
                new_room = Room(code=room_code)
                db.session.add(new_room)
                db.session.commit()
                
                print(f"Created new room with code: {room_code}")  # Debug print
                
                # stores room info in session
                session["room"] = room_code
                session["name"] = username
                return redirect(url_for("room"))
            except Exception as e:
                print(f"Error creating room: {e}")
                return render_template("home.html", error="Failed to create room: " + str(e), name=username)
        
        # Joins an existing room
        elif "join" in request.form:
            if not code:
                return render_template("home.html", error="Please enter a room code.", code=code, name=username)
            
            # Check if room exists in database
            existing_room = Room.query.filter_by(code=code).first()
            if not existing_room:
                return render_template("home.html", error="Room does not exist.", code=code, name=username)
            
            # Stores room info in session
            session["room"] = code
            session["name"] = username
            return redirect(url_for("room"))

    # Displays home page for GET request
    return render_template("home.html", name=username)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template("register.html", error="Username already exists")
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return render_template("register.html", error="Email already in use")
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for("login"))
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()
        
        # Brute-force protection
        if user and user.is_locked:
            # Check if lock should be removed
            if user.last_failed_login and (datetime.utcnow() - user.last_failed_login).total_seconds() > 1800:
                user.is_locked = False
                user.failed_login_attempts = 0
                db.session.commit()
            else:
                return render_template("login.html", error="Account is locked. Try again later")
        
        if user and user.check_password(password):
            # Reset failed attempts
            user.failed_login_attempts = 0
            user.is_locked = False
            db.session.commit()
            
            # Sets up session
            session["user_id"] = user.id
            session["username"] = user.username
            
            return redirect(url_for("home"))
        else:
            # Increments failed login attempts
            if user:
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                
                # Locks account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.is_locked = True
                
                db.session.commit()
            
            return render_template("login.html", error="Invalid username or password")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    session.modified = True
    return redirect(url_for("login"))

@app.route("/room")
def room():
    # Check if user is logged in
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    # Validate room session data
    room_code = session.get("room")
    
    if room_code is None:
        return redirect(url_for("home"))
    
    # Get room from database
    room_obj = Room.query.filter_by(code=room_code).first()
    if not room_obj:
        # Room doesn't exist in database
        if "room" in session:
            session.pop("room")
        return redirect(url_for("home"))
    
    # Renders room template
    return render_template("room.html", code=room_code, messages=room_obj.messages_list, 
                      username=session.get("username"))

@app.route("/users")
def users():
    # Check if user is logged in
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    try:
        # Make sure current_user_id is an integer
        current_user_id = int(session.get("user_id"))
        
        # Get all users except the current user
        users_list = User.query.filter(User.id != current_user_id).all()
        
        # Get unread message counts for each user
        unread_counts = {}
        for user in users_list:
            count = DirectMessage.query.filter_by(
                sender_id=user.id,
                recipient_id=current_user_id,
                is_read=False
            ).count()
            if count > 0:
                unread_counts[user.id] = count
        
        return render_template("users.html", users=users_list, unread_counts=unread_counts)
    except Exception as e:
        # ***Logs the error***
        print(f"Error in users route: {e}")
        return render_template("home.html", error="An error occurred when trying to view users. Please try again.")

@app.route("/direct_chat/<int:user_id>")
def direct_chat(user_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    # Ensure all needed session variables are set
    if not session.get("username"):
        return redirect(url_for("logout"))
    
    other_user = User.query.get_or_404(user_id)
    
    # Get messages between the two users
    messages = DirectMessage.query.filter(
        or_(
            and_(DirectMessage.sender_id == session["user_id"], 
                 DirectMessage.recipient_id == user_id),
            and_(DirectMessage.sender_id == user_id, 
                 DirectMessage.recipient_id == session["user_id"])
        )
    ).order_by(DirectMessage.timestamp).all()
    
    return render_template("direct_chat.html", 
                           other_user=other_user, 
                           messages=messages)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if not session.get("user_id"):
        return jsonify({"error": "Not authenticated"}), 401
    
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']

    # If user does not select a file, browser also submits an empty part without filename
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    
    try:
        # Read file data
        file_data = file.read()
        file_size = len(file_data)
        
        # Encrypt the file
        encrypted_data, encryption_key = SharedFile.encrypt_file(file_data)
        
        # Generate a secure filename
        original_filename = secure_filename(file.filename)
        file_type = original_filename.rsplit('.', 1)[1].lower()
        
        # Generate a unique filename
        unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{session.get('user_id')}_{original_filename}"
        
        # Save encrypted file
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        
        # Save file metadata to database
        new_file = SharedFile(
            filename=unique_filename,
            original_filename=original_filename,
            file_type=file_type,
            file_size=file_size,
            uploader_id=session.get("user_id"),
            encryption_key=base64.b64encode(encryption_key).decode('utf-8')
        )
        
        # Set room or direct message relationship based on request data
        room_code = request.form.get("room_code")
        recipient_id = request.form.get("recipient_id")
        
        if room_code:
            new_file.room_code = room_code
            new_file.is_direct_message = False
            
            # Create a message for the file in the room
            file_message = RoomMessage(
                room_code=room_code,
                sender_name=session.get("username"),
                sender_id=session.get("user_id"),
                content=f"Shared a file: {original_filename}",
                is_file=True
            )
            db.session.add(file_message)
            db.session.flush()  # Generate ID without committing
            
            new_file.file_id = file_message.id
            
        elif recipient_id:
            new_file.is_direct_message = True
            
            # Create a direct message for the file
            file_message = DirectMessage(
                sender_id=session.get("user_id"),
                recipient_id=int(recipient_id),
                content=f"Shared a file: {original_filename}",
                is_file=True
            )
            db.session.add(file_message)
            db.session.flush()  # Generate ID without committing
            
            new_file.direct_message_id = file_message.id
        
        db.session.add(new_file)
        db.session.commit()
        
        # Update the message with the file ID
        if room_code:
            file_message.file_id = new_file.id
        elif recipient_id:
            file_message.file_id = new_file.id
        
        db.session.commit()
        
        # Get uploader username for logging
        uploader_name = session.get("username", "Unknown User")
        
        # Log file upload based on message type
        if room_code:
            # Log file upload to room log
            log_path = active_log_sessions.get(f"room_{room_code}")
            if log_path:
                chat_logger.log_file_share(log_path, uploader_name, original_filename)
                # Update activity timestamp
                update_active_timestamp(f"room_{room_code}")
                
        elif recipient_id:
            # Log file upload to direct chat log
            participants = sorted([session.get("user_id"), int(recipient_id)])
            log_session_key = f"direct_{participants[0]}_{participants[1]}"
            log_path = active_log_sessions.get(log_session_key)
            if log_path:
                chat_logger.log_file_share(log_path, uploader_name, original_filename)
                # Update activity timestamp
                update_active_timestamp(log_session_key)
        
        # Return success response with file details
        response = {
            "success": True,
            "file_id": new_file.id,
            "filename": original_filename,
            "message_id": file_message.id
        }
        
        # Emit socket event depending on message type
        if room_code:
            socketio.emit("message", {
                "name": session.get("username"),
                "message": f"Shared a file: {original_filename}",
                "is_file": True,
                "file_id": new_file.id,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }, to=room_code)
        elif recipient_id:
            # Create a unique room name for this direct chat
            participants = sorted([session.get("user_id"), int(recipient_id)])
            direct_room = f"direct_{participants[0]}_{participants[1]}"
            
            socketio.emit("direct_message", {
                "sender_name": session.get("username"),
                "sender_id": session.get("user_id"),
                "content": f"Shared a file: {original_filename}",
                "is_file": True,
                "file_id": new_file.id,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }, to=direct_room)
        
        return jsonify(response), 200
    
    except Exception as e:
        print(f"Error uploading file: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/download_file/<int:file_id>")
def download_file(file_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    # Get file from database
    shared_file = SharedFile.query.get_or_404(file_id)
    
    # Check if user has access to the file
    if shared_file.is_direct_message:
        # Check if user is sender or recipient
        direct_message = shared_file.direct_message
        if direct_message and (direct_message.sender_id != session.get("user_id") and direct_message.recipient_id != session.get("user_id")):
            return "Unauthorized", 403
    else:
        # checks if user is in the room.. work on this later
            return "Unauthorized", 403
    
    try:
        # Read the encrypted file
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], shared_file.filename)
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        
        # Decrypt the file
        encryption_key = base64.b64decode(shared_file.encryption_key)
        decrypted_data = SharedFile.decrypt_file(encrypted_data, encryption_key)
        
        # Create a temporary file for the decrypted content
        temp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"temp_{shared_file.filename}")
        with open(temp_path, "wb") as f:
            f.write(decrypted_data)
        
        # Send the file to the user
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=shared_file.original_filename,
            mimetype=f"application/{shared_file.file_type}"
        )
    
    except Exception as e:
        print(f"Error downloading file: {e}")
        return "Error downloading file", 500


@socketio.on("message")
def message(data):
    room_code = session.get("room")
    name = session.get("name")
    user_id = session.get("user_id")
    
    if not room_code or not name or not user_id:
        print("Missing session data in message handler")
        return
    
    # Get room from database
    room = Room.query.filter_by(code=room_code).first()
    if not room:
        return
    
    # Checks if user is in cooldown
    current_time = time()
    if user_id in user_cooldowns and current_time < user_cooldowns[user_id]:
        # Calculate remaining cooldown time
        remaining = int(user_cooldowns[user_id] - current_time)
        # Sends message to the user about rate limiting
        send({
            "name": "System",
            "message": f"Rate limit exceeded. Please wait {remaining} seconds before sending more messages."
        }, to=request.sid) 
        
        # Log rate limit message to user's log file
        log_path = active_log_sessions.get(f"room_{room_code}")
        if log_path:
            chat_logger.log_system_message(log_path, f"Rate limit applied to {name}: {remaining}s cooldown")
        
        return
    
    # Cleans up old messages from history
    message_history[user_id] = [msg_time for msg_time in message_history[user_id] 
                               if current_time - msg_time < RATE_LIMIT["TIME_WINDOW"]]
    
    # Check if user has exceeded rate limit
    if len(message_history[user_id]) >= RATE_LIMIT["MAX_MESSAGES"]:
        # Apply cooldown
        user_cooldowns[user_id] = current_time + RATE_LIMIT["COOLDOWN"]
        # Let users know about rate limiting
        send({
            "name": "System",
            "message": f"Rate limit exceeded. Please wait {RATE_LIMIT['COOLDOWN']} seconds before sending more messages."
        }, to=request.sid)  # Send only to this client
        
        # Log rate limit message
        log_path = active_log_sessions.get(f"room_{room_code}")
        if log_path:
            chat_logger.log_system_message(log_path, f"Rate limit exceeded for {name}: {RATE_LIMIT['COOLDOWN']}s cooldown applied")
        
        return
    
    # Record this message timestamp
    message_history[user_id].append(current_time)
    
    # Create new message in the database
    new_message = RoomMessage(
        room_code=room_code,
        sender_name=name,
        sender_id=user_id,
        content=data["data"]
    )
    db.session.add(new_message)
    db.session.commit()
    
    content = {
        "name": name,
        "message": data["data"]
    }

    send(content, to=room_code)
    
    # Log the message to the room's log file
    log_path = active_log_sessions.get(f"room_{room_code}")
    if log_path:
        message_time = datetime.utcnow()
        chat_logger.log_room_message(log_path, name, data["data"], message_time)
    
    print(f"{name} said in room {room_code}: {data['data']}")

@socketio.on("direct_message")
def handle_direct_message(data):
    sender_id = session.get("user_id")
    sender_name = session.get("username")
    recipient_id = int(data.get("recipient_id"))
    content = data.get("content")
    
    if not sender_id or not recipient_id or not content:
        return
    
    # Create a unique key for this direct chat's log session
    participants = sorted([sender_id, recipient_id])
    log_session_key = f"direct_{participants[0]}_{participants[1]}"
    
    # Rate limiting checks
    current_time = time()
    if sender_id in user_cooldowns and current_time < user_cooldowns[sender_id]:
        remaining = int(user_cooldowns[sender_id] - current_time)
        # Send message about rate limiting
        socketio.emit("direct_message", {
            "sender_name": "System",
            "sender_id": 0,
            "content": f"Rate limit exceeded. Please wait {remaining} seconds before sending more messages.",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }, to=request.sid)
        
        # Log rate limit message
        log_path = active_log_sessions.get(log_session_key)
        if log_path:
            chat_logger.log_system_message(log_path, f"Rate limit applied to {sender_name}: {remaining}s cooldown")
        
        return
    
    # Clean up old messages from history
    message_history[sender_id] = [msg_time for msg_time in message_history[sender_id] 
                           if current_time - msg_time < RATE_LIMIT["TIME_WINDOW"]]
    
    # Check if user has exceeded rate limit
    if len(message_history[sender_id]) >= RATE_LIMIT["MAX_MESSAGES"]:
        # Apply cooldown
        user_cooldowns[sender_id] = current_time + RATE_LIMIT["COOLDOWN"]
        # Let user know about rate limiting
        socketio.emit("direct_message", {
            "sender_name": "System",
            "sender_id": 0,
            "content": f"Rate limit exceeded. Please wait {RATE_LIMIT['COOLDOWN']} seconds before sending more messages.",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }, to=request.sid)
        
        # Log rate limit message
        log_path = active_log_sessions.get(log_session_key)
        if log_path:
            chat_logger.log_system_message(log_path, f"Rate limit exceeded for {sender_name}: {RATE_LIMIT['COOLDOWN']}s cooldown applied")
        
        return
    
    # Record message timestamp
    message_history[sender_id].append(current_time)
    
    # Save message to database
    message = DirectMessage(
        sender_id=sender_id,
        recipient_id=recipient_id,
        content=content
    )
    db.session.add(message)
    db.session.commit()
    
    # Create a unique room name for this direct chat
    room_name = f"direct_{participants[0]}_{participants[1]}"
    
    # Send the message to the room
    socketio.emit("direct_message", {
        "sender_name": sender_name,
        "sender_id": sender_id,
        "content": content,
        "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    }, to=room_name)
    
    # Log the message
    log_path = active_log_sessions.get(log_session_key)
    if log_path:
        chat_logger.log_direct_message(log_path, sender_name, content, message.timestamp)
    
    print(f"Direct message from {sender_name} to {recipient_id}: {content}")

@socketio.on("join_direct_chat")
def handle_join_direct_chat(data):
    user_id = session.get("user_id")
    
    if not user_id:
        return
    
    recipient_id = int(data.get("recipient_id"))
    
    # Create a unique room name for this direct chat
    participants = sorted([user_id, recipient_id])
    room_name = f"direct_{participants[0]}_{participants[1]}"
    
    join_room(room_name)
    
    # Start a new log session for this direct chat if not already active
    log_session_key = f"direct_{participants[0]}_{participants[1]}"
    if log_session_key not in active_log_sessions:
        # Get user names
        current_user = User.query.get(user_id)
        recipient_user = User.query.get(recipient_id)
        
        if current_user and recipient_user:
            log_path = chat_logger.start_direct_session(
                user_id, current_user.username,
                recipient_id, recipient_user.username
            )
            if log_path:
                active_log_sessions[log_session_key] = log_path
                chat_logger.log_system_message(log_path, f"{current_user.username} started a chat with {recipient_user.username}")
    
    print(f"User {user_id} joined direct chat room {room_name}")

@socketio.on("connect")
def connect():
    room_code = session.get("room")
    name = session.get("name")
    user_id = session.get("user_id")
    
    # Validataion 
    if not room_code or not name or not user_id:
        return
    
    # Gets room from database
    room = Room.query.filter_by(code=room_code).first()
    if not room:
        return
    
    join_room(room_code)
    send({"name": name, "message": "has entered the room"}, to=room_code)
    
    # Increment member count
    room.members_count += 1
    db.session.commit()
    
    # Start a new log session for this room if not already active
    if f"room_{room_code}" not in active_log_sessions:
        log_path = chat_logger.start_room_session(room_code, name)
        if log_path:
            active_log_sessions[f"room_{room_code}"] = log_path
            # Log the user join event
            chat_logger.log_system_message(log_path, f"{name} has entered the room")
    
    print(f"{name} joined room {room_code}")

@socketio.on("disconnect")
def disconnect():
    room_code = session.get("room")
    name = session.get("name")
    
    if room_code:
        leave_room(room_code)
        
        # Get room from database
        room = Room.query.filter_by(code=room_code).first()
        if room:
            # Decrement member count
            room.members_count = max(0, room.members_count - 1)
            db.session.commit()
            
            # Send disconnection message
            send({"name": name, "message": "has left the room"}, to=room_code)
            
            # Log the users leave event
            log_path = active_log_sessions.get(f"room_{room_code}")
            if log_path:
                chat_logger.log_system_message(log_path, f"{name} has left the room")
                
                # If no users left in the room, end the log session
                if room.members_count == 0:
                    chat_logger.end_session(log_path)
                    active_log_sessions.pop(f"room_{room_code}", None)
            
            print(f"{name} has left the room {room_code}")

@socketio.on('reconnect')
def handle_reconnect():
    # ***triggered when a client reconnects after a disconnection***
    room_code = session.get("room")
    name = session.get("name")
    
    if room_code and name:
        # Gets room from database
        room = Room.query.filter_by(code=room_code).first()
        if room:
            join_room(room_code)
            
            # Gets recent messages from the database
            recent_messages = [
                {
                    "name": msg.sender_name,
                    "message": msg.content
                }
                for msg in room.messages.order_by(RoomMessage.timestamp.desc()).limit(5).all()[::-1]
            ]
            
            # Send recent messages to the reconnected client
            for msg in recent_messages:
                send(msg, to=request.sid)

@socketio.on("rejoin_room")
def handle_rejoin(data):
    """Handle client reconnection after server restart"""
    room_code = data.get('room')
    name = data.get('name')
    
    if not room_code or not name:
        return
    
    # Check if the room exists in the database
    room = Room.query.filter_by(code=room_code).first()
    if not room:
        # Create the room if it doesn't exist
        room = Room(code=room_code)
        db.session.add(room)
        db.session.commit()
    
    # Joins the room
    join_room(room_code)
    room.members_count += 1
    db.session.commit()
    
    # Announce to everyone the user has rejoined
    send({"name": name, "message": "has rejoined the room after a disconnection"}, to=room_code)
    print(f"{name} rejoined room {room_code} after reconnection")


# Helper function to get file icon class based on file type
def get_file_icon_class(file_type):
    document_types = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}
    image_types = {"png", "jpg", "jpeg", "gif"}
    archive_types = {"zip", "rar", "7z"}
    
    if file_type.lower() in document_types:
        return "document"
    elif file_type.lower() in image_types:
        return "image"
    elif file_type.lower() in archive_types:
        return "archive"
    else:
        return "other"

@app.context_processor
def utility_processor():
    return dict(get_file_icon_class=get_file_icon_class)

# Cleanup fun for temporary files
def cleanup_temp_files():
    temp_dir = app.config["UPLOAD_FOLDER"]
    current_time = time()
    
    for filename in os.listdir(temp_dir):
        if filename.startswith("temp_"):
            file_path = os.path.join(temp_dir, filename)
            # Remove temp files older than 1 hour
            if os.path.isfile(file_path) and current_time - os.path.getmtime(file_path) > 3600:
                os.remove(file_path)

if __name__ == "__main__":
    # Run cleanup on startup
    cleanup_temp_files()
    cleanup_inactive_log_sessions()
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000 , ssl_context=None)