import sqlite3
from datetime import datetime
import threading
import queue


class DatabaseManager:
    def __init__(self, db_name='user_scores.db'):
        """Initialize database connection"""
        self.db_name = db_name
        self.thread_local = threading.local()
        self.lock = threading.Lock()

    def get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self.thread_local, "connection"):
            self.thread_local.connection = self.create_database()
        return self.thread_local.connection

    def create_database(self):
        """Create database with enhanced schema for 2FA support"""
        try:
            conn = sqlite3.connect(self.db_name, check_same_thread=False)
            cursor = conn.cursor()

            # Users table with additional fields for 2FA
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone_number TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                totp_secret TEXT,
                verification_method TEXT DEFAULT 'email',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_verification_attempt TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                account_status TEXT DEFAULT 'active'
            )
            ''')

            # Enhanced auth_logs table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT,
                success BOOLEAN,
                ip_address TEXT,
                device_info TEXT,
                verification_method TEXT,
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
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('SELECT * FROM users WHERE email = ? AND account_status = "active"', (email,))
                return cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error retrieving user: {e}")
            return None

    def create_user(self, name, email, phone_number, password_hash, totp_secret):
        """Create a new user"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('''
                INSERT INTO users (
                    name, email, phone_number, password_hash, 
                    totp_secret, created_at, account_status
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'active')
                ''', (name, email, phone_number, password_hash, totp_secret))

                self.get_connection().commit()
                return True
        except sqlite3.IntegrityError:
            return False
        except sqlite3.Error:
            return False

    def update_failed_attempts(self, user_id):
        """Update failed login attempts"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('''
                UPDATE users 
                SET failed_attempts = failed_attempts + 1,
                    last_verification_attempt = CURRENT_TIMESTAMP
                WHERE id = ?
                ''', (user_id,))

                cursor.execute('SELECT failed_attempts FROM users WHERE id = ?', (user_id,))
                attempts = cursor.fetchone()[0]

                if attempts >= 10:
                    cursor.execute('''
                    UPDATE users 
                    SET account_status = 'locked'
                    WHERE id = ?
                    ''', (user_id,))

                self.get_connection().commit()
                return True
        except sqlite3.Error:
            if self.get_connection():
                self.get_connection().rollback()
            return False

    def reset_failed_attempts(self, user_id):
        """Reset failed attempts and update login timestamp"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('''
                UPDATE users 
                SET failed_attempts = 0,
                    last_login = CURRENT_TIMESTAMP,
                    account_status = 'active'
                WHERE id = ?
                ''', (user_id,))
                self.get_connection().commit()
                return True
        except sqlite3.Error:
            if self.get_connection():
                self.get_connection().rollback()
            return False

    def log_auth_attempt(self, user_id, action, success, ip_address, device_info=None, verification_method=None):
        """Log authentication attempts"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('''
                INSERT INTO auth_logs (
                    user_id, action, success, ip_address, 
                    device_info, verification_method
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, action, success, ip_address, device_info, verification_method))
                self.get_connection().commit()
                return True
        except sqlite3.Error:
            if self.get_connection():
                self.get_connection().rollback()
            return False

    def update_verification_method(self, user_id, method):
        """Update user's preferred verification method"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('''
                UPDATE users 
                SET verification_method = ?
                WHERE id = ?
                ''', (method, user_id))
                self.get_connection().commit()
                return True
        except sqlite3.Error:
            if self.get_connection():
                self.get_connection().rollback()
            return False

    def get_user_verification_method(self, user_id):
        """Get user's preferred verification method"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('SELECT verification_method FROM users WHERE id = ?', (user_id,))
                result = cursor.fetchone()
                return result[0] if result else 'email'
        except sqlite3.Error:
            return 'email'

    def update_last_verification(self, user_id):
        """Update last verification timestamp"""
        try:
            with self.lock:
                cursor = self.get_connection().cursor()
                cursor.execute('''
                UPDATE users 
                SET last_verification_attempt = CURRENT_TIMESTAMP
                WHERE id = ?
                ''', (user_id,))
                self.get_connection().commit()
                return True
        except sqlite3.Error:
            if self.get_connection():
                self.get_connection().rollback()
            return False

    def close(self):
        """Close database connection"""
        try:
            if hasattr(self.thread_local, "connection"):
                self.thread_local.connection.close()
                del self.thread_local.connection
        except Exception as e:
            print(f"Error closing database: {e}")