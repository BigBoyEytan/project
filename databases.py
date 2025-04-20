import sqlite3
from datetime import datetime
import threading
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureDatabaseManager:
    def __init__(self, db_name='user_scores.db', encryption_key=None):
        """Initialize database connection with encryption"""
        if not encryption_key:
            encryption_key = os.urandom(32)

        # Initialize encryption
        salt = b'secure_salt_for_db'  # In production, store this securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(encryption_key))
        self.cipher_suite = Fernet(key)

        # Database setup
        self.db_name = self._encrypt_string(db_name)
        self.thread_local = threading.local()
        self.lock = threading.Lock()

        # Ensure database is created
        self.get_connection()

    def get_connection(self):
        """Get thread-local database connection with WAL mode"""
        if not hasattr(self.thread_local, "connection"):
            self.thread_local.connection = self.create_database()
            # Enable Write-Ahead Logging for better concurrency
            self.thread_local.connection.execute('PRAGMA journal_mode=WAL')
            # Enable foreign key constraints
            self.thread_local.connection.execute('PRAGMA foreign_keys=ON')
        return self.thread_local.connection

    def create_database(self):
        """Create database with schema including lookup fields"""
        try:
            conn = sqlite3.connect(self._decrypt_string(self.db_name),
                                   check_same_thread=False,
                                   isolation_level='EXCLUSIVE')
            cursor = conn.cursor()

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                verification_method TEXT DEFAULT 'email',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                account_status TEXT DEFAULT 'active',
                security_questions TEXT,
                email_lookup TEXT,
                CHECK (account_status IN ('active', 'locked', 'disabled', 'pending_verification'))
            )
            ''')

            # Check if the lookup columns exist, add them if they don't
            try:
                cursor.execute("SELECT email_lookup FROM users LIMIT 1")
            except sqlite3.OperationalError:
                # Column doesn't exist, add it
                cursor.execute("ALTER TABLE users ADD COLUMN email_lookup TEXT")
                print("Added email_lookup column to users table")

            # Removed phone_lookup checks and migration

            conn.commit()
            return conn
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None

    def _update_existing_records(self, conn):
        """Update existing records to add lookup values if needed"""
        try:
            cursor = conn.cursor()

            # Get users that need updating (where lookup fields are NULL)
            cursor.execute('''
                SELECT id, email, phone_number 
                FROM users 
                WHERE email_lookup IS NULL OR phone_lookup IS NULL
            ''')

            users_to_update = cursor.fetchall()
            if not users_to_update:
                return

            print(f"Updating lookup fields for {len(users_to_update)} existing users")

            for user_id, encrypted_email, encrypted_phone in users_to_update:
                try:
                    email = self._decrypt_string(encrypted_email)
                    phone = self._decrypt_string(encrypted_phone)

                    email_lookup = self._deterministic_encrypt(email)
                    phone_lookup = self._deterministic_encrypt(phone)

                    cursor.execute('''
                        UPDATE users 
                        SET email_lookup = ?, phone_lookup = ? 
                        WHERE id = ?
                    ''', (email_lookup, phone_lookup, user_id))

                except Exception as e:
                    print(f"Error updating user {user_id}: {e}")

            conn.commit()
            print("Lookup field update completed")

        except Exception as e:
            print(f"Error in update_existing_records: {e}")

    def check_user_exists(self, email):
        """
        Check if a user with given email exists.

        Args:
            email (str): User's email

        Returns:
            bool: True if user exists, False otherwise
        """
        try:
            # Use deterministic encryption for lookups
            email_lookup = self._deterministic_encrypt(email)

            cursor = self.get_connection().cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM users 
                WHERE email_lookup = ?
            ''', (email_lookup,))

            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print(f"Error checking user existence: {e}")
            # In case of any error, prevent registration
            return True

    def create_user(self, name, email, password_hash, password_salt):
        """Create a new user without phone number"""
        try:
            with self.lock:
                # Encrypt user details
                encrypted_name = self._encrypt_string(name)
                encrypted_email = self._encrypt_string(email)

                # Create deterministic encryption for lookups
                email_lookup = self._deterministic_encrypt(email)

                # Start a transaction
                conn = self.get_connection()
                cursor = conn.cursor()

                # Check if user exists before attempting to insert
                cursor.execute('''
                    SELECT COUNT(*) FROM users 
                    WHERE email_lookup = ?
                ''', (email_lookup,))

                # If user already exists, return False
                if cursor.fetchone()[0] > 0:
                    return False

                # If no existing user, proceed with insertion
                cursor.execute('''
                INSERT INTO users (
                    name, email, password_hash, 
                    password_salt, created_at, account_status, 
                    verification_method, email_lookup
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 'active', 'email', ?)
                ''', (
                    encrypted_name,
                    encrypted_email,
                    password_hash,
                    password_salt,
                    email_lookup
                ))

                conn.commit()
                return True
        except sqlite3.IntegrityError:
            # This catches unique constraint violations
            return False
        except Exception as e:
            print(f"Error creating user: {e}")
            if self.get_connection():
                self.get_connection().rollback()
            return False

    def get_user_by_email(self, email):
        """
        Retrieve user information by email using deterministic lookup
        """
        try:
            # Use deterministic encryption for lookup
            email_lookup = self._deterministic_encrypt(email)

            cursor = self.get_connection().cursor()
            # Modified query - removed phone_number column
            cursor.execute('''
                SELECT id, name, email, password_hash, password_salt,
                       score, verification_method, created_at, account_status
                FROM users 
                WHERE email_lookup = ?
            ''', (email_lookup,))

            user_data = cursor.fetchone()

            if user_data:
                # Decrypt sensitive fields - adjusted indexes since we removed phone_number
                decrypted_user = list(user_data)
                decrypted_user[1] = self._decrypt_string(decrypted_user[1])  # name
                decrypted_user[2] = self._decrypt_string(decrypted_user[2])  # email

                return tuple(decrypted_user)
            return None

        except Exception as e:
            print(f"Error retrieving user by email: {e}")
            return None



    def _encrypt_string(self, text):
        """Encrypt sensitive string data (non-deterministic)"""
        if text is None:
            return None
        if isinstance(text, str):
            return self.cipher_suite.encrypt(text.encode()).decode()
        return text

    def _decrypt_string(self, encrypted_text):
        """Decrypt sensitive string data"""
        if encrypted_text is None:
            return None
        if isinstance(encrypted_text, str):
            try:
                return self.cipher_suite.decrypt(encrypted_text.encode()).decode()
            except Exception as e:
                print(f"Error decrypting string: {e}")
                # Return a placeholder instead of the actual encrypted text
                return "[Decryption Error]"
        return encrypted_text

    def _deterministic_encrypt(self, text):
        """
        Deterministic encryption for searchable fields.
        The same input will always produce the same output, making it searchable.
        """
        if isinstance(text, str):
            # Use a consistent hashing approach
            hash_obj = hashlib.sha256(text.encode())
            # Add a fixed salt - this makes all lookups use the same salt
            salt = b'fixed_salt_for_lookups'
            hash_obj.update(salt)
            return hash_obj.hexdigest()
        return text

    def _encrypt_data(self, data):
        """Encrypt data before storing in database"""
        return self.cipher_suite.encrypt(json.dumps(data).encode()).decode()

    def _decrypt_data(self, encrypted_data):
        """Decrypt data retrieved from database"""
        try:
            return json.loads(self.cipher_suite.decrypt(encrypted_data.encode()))
        except Exception as e:
            print(f"Error decrypting data: {e}")
            return {}

    def close(self):
        """Close database connection"""
        try:
            if hasattr(self.thread_local, "connection"):
                self.thread_local.connection.commit()
                self.thread_local.connection.close()
                del self.thread_local.connection
        except Exception as e:
            print(f"Error closing database: {e}")


def view_database():
    """Simple database viewer for PyCharm console"""
    # Check for database files
    possible_dbs = ['user_scores.db', 'user_auth.db']
    found_dbs = [db for db in possible_dbs if os.path.exists(db)]

    if not found_dbs:
        print("No database files found in the current directory.")
        db_path = input("Enter the full path to your database file: ")
        if os.path.exists(db_path):
            found_dbs = [db_path]
        else:
            print(f"File not found: {db_path}")
            return

    # Select database to view
    if len(found_dbs) > 1:
        print("Multiple database files found:")
        for i, db in enumerate(found_dbs):
            print(f"{i + 1}. {db}")
        choice = int(input("Enter the number of the database to view: ")) - 1
        db_path = found_dbs[choice]
    else:
        db_path = found_dbs[0]

    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get list of tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    print(f"\nDatabase: {db_path}")
    print("Tables:")
    for i, table in enumerate(tables):
        print(f"{i + 1}. {table[0]}")

    # Select table to view
    table_choice = int(input("Enter the number of the table to view: ")) - 1
    table_name = tables[table_choice][0]

    # Get column names
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [col[1] for col in cursor.fetchall()]

    # Get row count
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    row_count = cursor.fetchone()[0]

    print(f"\nTable: {table_name}")
    print(f"Columns: {', '.join(columns)}")
    print(f"Total rows: {row_count}")

    # View data
    if row_count > 0:
        limit = min(row_count, 20)  # Show max 20 rows
        cursor.execute(f"SELECT * FROM {table_name} LIMIT {limit}")
        rows = cursor.fetchall()

        # Display column headers
        header = " | ".join(f"{col:<15}" for col in columns)
        print("\n" + header)
        print("-" * len(header))

        # Display rows
        for row in rows:
            formatted_row = " | ".join(f"{str(cell):<15}" for cell in row)
            print(formatted_row)

        if row_count > limit:
            print(f"\n(Showing {limit} of {row_count} rows)")

    conn.close()


def fix_existing_database(db_path='user_scores.db', encryption_key=b'secure_encryption_key_for_development'):
    """
    Fix existing database by adding lookup columns and populating them.
    This is a utility function to migrate existing databases.
    """
    print(f"Fixing database: {db_path}")

    try:
        # Initialize with the same encryption parameters as SecureDatabaseManager
        salt = b'secure_salt_for_db'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(encryption_key))
        cipher_suite = Fernet(key)

        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if we need to add the lookup columns
        try:
            cursor.execute("SELECT email_lookup FROM users LIMIT 1")
        except sqlite3.OperationalError:
            # Column doesn't exist, add it
            cursor.execute("ALTER TABLE users ADD COLUMN email_lookup TEXT")
            print("Added email_lookup column")

        try:
            cursor.execute("SELECT phone_lookup FROM users LIMIT 1")
        except sqlite3.OperationalError:
            # Column doesn't exist, add it
            cursor.execute("ALTER TABLE users ADD COLUMN phone_lookup TEXT")
            print("Added phone_lookup column")

        # Define decryption and deterministic encryption functions
        def decrypt_string(encrypted_text):
            if isinstance(encrypted_text, str):
                try:
                    return cipher_suite.decrypt(encrypted_text.encode()).decode()
                except Exception as e:
                    print(f"Error decrypting: {e}")
                    return ""
            return encrypted_text

        def deterministic_encrypt(text):
            if isinstance(text, str):
                hash_obj = hashlib.sha256(text.encode())
                salt = b'fixed_salt_for_lookups'
                hash_obj.update(salt)
                return hash_obj.hexdigest()
            return text

        # Get all users that need updating
        cursor.execute("SELECT id, email, phone_number FROM users WHERE email_lookup IS NULL OR phone_lookup IS NULL")
        users = cursor.fetchall()

        if not users:
            print("No users need updating")
            conn.close()
            return

        print(f"Updating {len(users)} users")
        for user_id, encrypted_email, encrypted_phone in users:
            try:
                # Decrypt values
                email = decrypt_string(encrypted_email)
                phone = decrypt_string(encrypted_phone)

                # Create lookup values
                email_lookup = deterministic_encrypt(email)
                phone_lookup = deterministic_encrypt(phone)

                # Update the record
                cursor.execute(
                    "UPDATE users SET email_lookup = ?, phone_lookup = ? WHERE id = ?",
                    (email_lookup, phone_lookup, user_id)
                )
                print(f"Updated user {user_id}")
            except Exception as e:
                print(f"Error updating user {user_id}: {e}")

        conn.commit()
        conn.close()
        print("Database fix completed successfully")

    except Exception as e:
        print(f"Error fixing database: {e}")


if __name__ == "__main__":
    # If run directly, show the database viewer
    choice = input("Choose an action:\n1. View database\n2. Fix existing database\nChoice: ")
    if choice == "1":
        view_database()
    elif choice == "2":
        fix_existing_database()
    else:
        print("Invalid choice")