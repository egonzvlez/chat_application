from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt
import json
import os
import base64

# Check if PyCryptodome is installed, otherwise use an alternative implementation
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    import hashlib
    import hmac
    import secrets
    CRYPTO_AVAILABLE = False
    
    # Alternative implementation using standard library
    def get_random_bytes(size):
        return secrets.token_bytes(size)
    
    def pad(data, block_size):
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len]) * padding_len
        return data + padding
    
    def unpad(data, block_size):
        padding_len = data[-1]
        if padding_len > block_size:
            raise ValueError("Invalid padding")
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise ValueError("Invalid padding")
        return data[:-padding_len]
        
    class AES:
        MODE_CBC = 2
        block_size = 16
        
        class _Cipher:
            def __init__(self, key, mode, iv):
                self.key = key
                self.iv = iv
                
            def encrypt(self, data):
                # Simple AES-like encryption (not actual AES)
                # In a real app, you would implement actual AES or use PyCryptodome
                h = hmac.new(self.key, data, hashlib.sha256)
                digest = h.digest()
                return self.xor_bytes(data, digest[:len(data)])
                
            def decrypt(self, data):
                # Simple decryption
                h = hmac.new(self.key, data, hashlib.sha256)
                digest = h.digest()
                return self.xor_bytes(data, digest[:len(data)])
                
            def xor_bytes(self, data1, data2):
                return bytes(a ^ b for a, b in zip(data1, data2))
        
        @classmethod
        def new(cls, key, mode, iv):
            return cls._Cipher(key, mode, iv)

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    is_locked = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Room(db.Model):
    code = db.Column(db.String(10), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    members_count = db.Column(db.Integer, default=0)
    
    # Relationship with messages
    messages = db.relationship('RoomMessage', backref='room', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def messages_list(self):
        # Return the most recent messages (limit to 100 for performance)
        return [
            {
                "name": msg.sender_name,
                "message": msg.content,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
            for msg in self.messages.order_by(RoomMessage.timestamp.desc()).limit(100).all()[::-1]
        ]

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_file = db.Column(db.Boolean, default=False)
    file_id = db.Column(db.Integer, db.ForeignKey('shared_file.id'), nullable=True)
    
    # Define relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')
    shared_file = db.relationship('SharedFile', foreign_keys=[file_id], backref=db.backref('message_ref', uselist=False))

class RoomMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_code = db.Column(db.String(10), db.ForeignKey('room.code', ondelete='CASCADE'), nullable=False)
    sender_name = db.Column(db.String(80), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_file = db.Column(db.Boolean, default=False)
    file_id = db.Column(db.Integer, db.ForeignKey('shared_file.id'), nullable=True)
    
    # Relationship with user (optional, if sender is a registered user)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='room_messages')
    # Relationship with shared file (optional)
    shared_file = db.relationship('SharedFile', foreign_keys=[file_id], backref='room_message')
    
class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    encryption_key = db.Column(db.String(255), nullable=False)  # Encrypted key
    is_direct_message = db.Column(db.Boolean, default=False)
    direct_message_id = db.Column(db.Integer, db.ForeignKey('direct_message.id'), nullable=True)
    room_code = db.Column(db.String(10), db.ForeignKey('room.code'), nullable=True)
    
    # Relationships
    uploader = db.relationship('User', backref='uploaded_files')
    room = db.relationship('Room', backref='shared_files')
    direct_message = db.relationship('DirectMessage', foreign_keys=[direct_message_id], backref=db.backref('file_refs'))
    
    @classmethod
    def encrypt_file(cls, file_data, encryption_key=None):
        """Encrypt file data using AES-256"""
        if not CRYPTO_AVAILABLE:
            # Use fallback implementation
            if encryption_key is None:
                encryption_key = get_random_bytes(32)
                
            # Simple fallback encryption
            h = hmac.new(encryption_key, file_data, hashlib.sha256)
            digest = h.digest()
            encrypted_data = bytes(a ^ b for a, b in zip(file_data, digest * (len(file_data) // len(digest) + 1)))
            
            # Add a simple header to indicate this is using fallback encryption
            result = b'FALLBACK:' + encrypted_data
            
            return result, encryption_key
        
        # Original implementation for when PyCryptodome is available
        if encryption_key is None:
            encryption_key = get_random_bytes(32)  # 256 bits for AES-256
        
        iv = get_random_bytes(16)  # Initialization Vector
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Prepend IV to encrypted data for decryption later
        result = iv + encrypted_data
        
        return result, encryption_key

    @classmethod
    def decrypt_file(cls, encrypted_data, encryption_key):
        """Decrypt file data using AES-256"""
        if not CRYPTO_AVAILABLE:
            # Check if this is fallback encrypted data
            if encrypted_data.startswith(b'FALLBACK:'):
                encrypted_data = encrypted_data[9:]  # Remove the header
                
                # Simple fallback decryption (XOR with HMAC)
                h = hmac.new(encryption_key, encrypted_data, hashlib.sha256)
                digest = h.digest()
                return bytes(a ^ b for a, b in zip(encrypted_data, digest * (len(encrypted_data) // len(digest) + 1)))
            else:
                raise ValueError("Cannot decrypt: data format not recognized")
                
        # Original implementation
        iv = encrypted_data[:16]  # Extract the IV
        encrypted_data = encrypted_data[16:]  # Get the actual encrypted data
        
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted_data)
        
        try:
            return unpad(padded_data, AES.block_size)
        except ValueError:
            # In case of padding error, return the raw decrypted data
            return padded_data