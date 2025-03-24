import os
from datetime import datetime

class ChatLogger:
    def __init__(self, base_log_dir="chat_logs"):
        """Initializes the chat logger with a base directory for logs."""
        self.base_log_dir = base_log_dir
        self._ensure_log_directory_exists()
        
    def _ensure_log_directory_exists(self):
        """Ensure the log directory exists, create it if it doesn't."""
        if not os.path.exists(self.base_log_dir):
            os.makedirs(self.base_log_dir)
            
        # Create subdirectories for room and direct chats
        room_dir = os.path.join(self.base_log_dir, "rooms")
        direct_dir = os.path.join(self.base_log_dir, "direct")
        
        if not os.path.exists(room_dir):
            os.makedirs(room_dir)
            
        if not os.path.exists(direct_dir):
            os.makedirs(direct_dir)
    
    def _get_room_log_path(self, room_code):
        """Get the path to the log file for a specific room."""
        # Create a directory for this specific room if it doesn't exist
        room_dir = os.path.join(self.base_log_dir, "rooms", room_code)
        if not os.path.exists(room_dir):
            os.makedirs(room_dir)
        # Format
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        return os.path.join(room_dir, f"{timestamp}.txt")
    
    def _get_direct_log_path(self, user1_id, user2_id):
        """Get the path to the log file for a direct chat between two users."""
        # Sort user IDs
        participants = sorted([user1_id, user2_id])
        direct_chat_id = f"{participants[0]}_{participants[1]}"
        
        # Create a directory for direct chat if it doesn't exist
        direct_dir = os.path.join(self.base_log_dir, "direct", direct_chat_id)
        if not os.path.exists(direct_dir):
            os.makedirs(direct_dir)
        
        # Format
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        return os.path.join(direct_dir, f"{timestamp}.txt")
    
    def start_room_session(self, room_code, creator_name):
        """Start a new logging session for a room chat."""
        log_path = self._get_room_log_path(room_code)
        
        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                header = f"Room Chat: {room_code}\n"
                header += f"Session Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                header += f"Created by: {creator_name}\n"
                header += "-" * 80 + "\n\n"
                f.write(header)
            
            return log_path
        except Exception as e:
            print(f"Error starting room session log: {e}")
            return None
    
    def start_direct_session(self, user1_id, user1_name, user2_id, user2_name):
        """Start a new logging session for a direct chat."""
        log_path = self._get_direct_log_path(user1_id, user2_id)
        
        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                header = f"Direct Chat between {user1_name} and {user2_name}\n"
                header += f"Session Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                header += "-" * 80 + "\n\n"
                f.write(header)
            
            return log_path
        except Exception as e:
            print(f"Error starting direct session log: {e}")
            return None
    
    def log_room_message(self, log_path, sender_name, message_content, timestamp=None):
        """Log a message sent in a room chat."""
        if not timestamp:
            timestamp = datetime.utcnow()
            
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {sender_name}: {message_content}\n"
                f.write(log_entry)
            
            return True
        except Exception as e:
            print(f"Error logging room message: {e}")
            return False
    
    def log_direct_message(self, log_path, sender_name, message_content, timestamp=None):
        """Log a message sent in a direct chat."""
        if not timestamp:
            timestamp = datetime.utcnow()
            
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {sender_name}: {message_content}\n"
                f.write(log_entry)
            
            return True
        except Exception as e:
            print(f"Error logging direct message: {e}")
            return False
    
    def log_system_message(self, log_path, message_content, timestamp=None):
        """Log a system message. """
        if not timestamp:
            timestamp = datetime.utcnow()
            
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] *SYSTEM*: {message_content}\n"
                f.write(log_entry)
            
            return True
        except Exception as e:
            print(f"Error logging system message: {e}")
            return False
    
    def log_file_share(self, log_path, sender_name, file_name, timestamp=None):
        """Log a file share event."""
        if not timestamp:
            timestamp = datetime.utcnow()
            
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {sender_name} shared a file: {file_name}\n"
                f.write(log_entry)
            
            return True
        except Exception as e:
            print(f"Error logging file share: {e}")
            return False
    
    def end_session(self, log_path):
        """End a chat session by adding a footer to the log file."""
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                footer = f"\n\nSession Ended: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                footer += "-" * 80 + "\n"
                f.write(footer)
            
            return True
        except Exception as e:
            print(f"Error ending session log: {e}")
            return False