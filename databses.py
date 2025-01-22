import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name='user_scores.db'):
        """Initialize database connection"""
        self.db_name = db_name
        self.conn = self.create_database()

    def create_database(self):
        """Create database with users and auth_logs tables"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone_number TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                totp_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0
            )
            ''')

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT,
                success BOOLEAN,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')

            conn.commit()
            return conn
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None

    def get_user_by_email(self, email):
        """Retrieve user by email"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        return cursor.fetchone()

    def create_user(self, name, email, phone_number, password_hash, totp_secret):
        """Create a new user"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            INSERT INTO users (name, email, phone_number, password_hash, totp_secret)
            VALUES (?, ?, ?, ?, ?)
            ''', (name, email, phone_number, password_hash, totp_secret))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_failed_attempts(self, user_id):
        """Update failed login attempts"""
        cursor = self.conn.cursor()
        cursor.execute('''
        UPDATE users 
        SET failed_attempts = failed_attempts + 1 
        WHERE id = ?
        ''', (user_id,))
        self.conn.commit()

    def reset_failed_attempts(self, user_id):
        """Reset failed attempts and update last login"""
        cursor = self.conn.cursor()
        cursor.execute('''
        UPDATE users 
        SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP 
        WHERE id = ?
        ''', (user_id,))
        self.conn.commit()

    def log_auth_attempt(self, user_id, action, success, ip_address):
        """Log authentication attempts"""
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO auth_logs (user_id, action, success, ip_address)
        VALUES (?, ?, ?, ?)
        ''', (user_id, action, success, ip_address))
        self.conn.commit()

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()