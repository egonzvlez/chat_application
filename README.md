# SecureChat - RT Chat Application
Web security Project 1 Part 2.
Enrique Gonzalez @egonzalez4467@csu.fullerton.edu

## Requirements

* Python 3.13.2

```
Flask==3.1.0
Flask-Migrate==4.0.5
Flask-SocketIO==5.5.1
Flask-SQLAlchemy==3.1.0
bcrypt==4.0.1
pycryptodome==3.22.0
and more...
```

`requirements.txt` has the complete list of dependencies.

## How to Run

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```
   flask db init
   flask db migrate
   flask db upgrade
   ```

3. Run the application:
   ```
   python main.py
   ```

4. Access the application in your browser at `https://localhost:5000`

## Features

- User authentication with brute-force protection
- Create and join chat rooms with unique room codes
- Direct messaging between users
- End-to-end encrypted file sharing
- Message formatting with markdown
- Emoji support
- Comprehensive chat logging
- Rate limiting to prevent abuse
- Reconnection handling for network disruptions

## AI Assistance

The project was completed with assistance of AI for: documentation creation and code review and enhancement suggestions.