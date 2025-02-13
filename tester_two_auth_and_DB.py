import unittest
import os
import sys
import secrets
import tempfile
from datetime import datetime, timedelta

# Ensure the project root is in the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from DB_and_related.databses import SecureDatabaseManager
from DB_and_related.two_factor_auth import AuthSystem


class TestAuthenticationSystem(unittest.TestCase):
    """Comprehensive test suite for Authentication System"""

    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        # Create temporary database
        cls.temp_db_file = os.path.join(tempfile.gettempdir(), f'test_auth_{secrets.token_hex(4)}.db')

        # Mock configurations
        cls.email_config = {
            'sender': 'test_sender@example.com',
            'password': 'test_password'
        }
        cls.twilio_config = {
            'sid': 'test_sid',
            'token': 'test_token',
            'phone': '+1234567890'
        }

        # Initialize database and auth system
        cls.db_manager = SecureDatabaseManager(cls.temp_db_file)
        cls.auth_system = AuthSystem(
            database_manager=cls.db_manager,
            email_config=cls.email_config,
            sms_config=cls.twilio_config
        )

    def generate_test_user(self, unique_suffix=None):
        """Generate unique test user data"""
        suffix = unique_suffix or secrets.token_hex(4)
        return {
            'name': f"Test User {suffix}",
            'email': f"test_{suffix}@example.com",
            'phone': f"+1{secrets.randbelow(9000000000) + 1000000000}",
            'password': f"SecurePass{suffix}!"
        }

    def test_comprehensive_email_validation(self):
        """Comprehensive test for email validation"""
        test_cases = {
            'valid': [
                'user@example.com',
                'user.name@example.co.uk',
                'user+tag@example.org',
                'first.last@domain.com',
                'user123@domain-name.com'
            ],
            'invalid': [
                'invalid_email',
                'invalid@',
                '@invalid.com',
                'invalid@invalid',
                'invalid@.com',
                'user@domain',
                'user@.com',
                'user@domain.',
                'user@domain..com',
                'a' * 255 + '@example.com'  # Too long local part
            ]
        }

        # Test valid emails
        for email in test_cases['valid']:
            with self.subTest(email=email):
                self.assertTrue(
                    self.auth_system.validate_email(email),
                    f"Valid email {email} should be accepted"
                )

        # Test invalid emails
        for email in test_cases['invalid']:
            with self.subTest(email=email):
                self.assertFalse(
                    self.auth_system.validate_email(email),
                    f"Invalid email {email} should be rejected"
                )

    def test_comprehensive_phone_validation(self):
        """Comprehensive test for phone number validation"""
        test_cases = {
            'valid': [
                '+14155552671',  # US number
                '+971501234567',  # UAE number
                '+447911123456',  # UK number
                '+525555555555',  # Mexico number
                '+819012345678'  # Japan number
            ],
            'invalid': [
                '1234567890',  # Missing +
                '+123',  # Too short
                '+123456789012345678',  # Too long
                'abc1234567890',  # Invalid characters
                '+1 234 567 8901',  # Contains spaces
                '+',  # Just + symbol
                '+ 1234567890',  # Space after +
                '+a1234567890',  # Non-digit after +
                ''  # Empty string
            ]
        }

        # Test valid phone numbers
        for phone in test_cases['valid']:
            with self.subTest(phone=phone):
                self.assertTrue(
                    self.auth_system.validate_phone(phone),
                    f"Valid phone {phone} should be accepted"
                )

        # Test invalid phone numbers
        for phone in test_cases['invalid']:
            with self.subTest(phone=phone):
                self.assertFalse(
                    self.auth_system.validate_phone(phone),
                    f"Invalid phone {phone} should be rejected"
                )

    def test_password_security(self):
        """Comprehensive password hashing and verification tests"""
        test_cases = [
            "StrongPass123!",
            "Special@Chars123",
            "LongPasswordWithManyCharacters!@#$%^&*()_+",
            "12345678",  # Weak password
            "a"  # Very short password
        ]

        for test_password in test_cases:
            with self.subTest(password=test_password):
                # Hash the password
                salt, hashed_password = self.auth_system.hash_password(test_password)

                # Verify correct password
                self.assertTrue(
                    self.auth_system.verify_password(
                        test_password,
                        f"{salt}:{hashed_password}"
                    ),
                    f"Password verification should succeed with correct password: {test_password}"
                )

                # Verify incorrect password
                self.assertFalse(
                    self.auth_system.verify_password(
                        "WrongPassword" + test_password,
                        f"{salt}:{hashed_password}"
                    ),
                    f"Password verification should fail with incorrect password for: {test_password}"
                )

    def test_registration_edge_cases(self):
        """Test edge cases in user registration"""
        # Scenario 1: Registration with very long name
        long_name_user = self.generate_test_user()
        long_name_user['name'] = 'A' * 100  # Very long name

        # Scenario 2: Registration with special characters in name
        special_name_user = self.generate_test_user()
        special_name_user['name'] = "User with @#$%^&* Special Chars"

        # Scenario 3: Registration with minimal valid inputs
        minimal_user = {
            'name': 'Min User',
            'email': f"min_{secrets.token_hex(4)}@min.com",
            'phone': f"+1{secrets.randbelow(9000000000) + 1000000000}",
            'password': 'MinPass123!'
        }

        # Test scenarios
        test_scenarios = [
            (long_name_user, True, "Long name registration"),
            (special_name_user, True, "Special characters in name"),
            (minimal_user, True, "Minimal valid input")
        ]

        for user, expected_success, scenario_desc in test_scenarios:
            with self.subTest(scenario=scenario_desc):
                success, message = self.auth_system.register_user(
                    user['name'], user['email'], user['phone'], user['password']
                )
                self.assertEqual(
                    success,
                    expected_success,
                    f"{scenario_desc} failed. Message: {message}"
                )

    def test_verification_code_advanced(self):
        """Advanced verification code tests"""
        # Generate test user
        user = self.generate_test_user()

        # Test 1: Generate and validate code immediately
        code1 = self.auth_system.generate_verification_code(user['email'])
        self.assertTrue(
            self.auth_system.validate_verification_code(user['email'], code1),
            "First validation should succeed"
        )

        # Test 2: Attempt to reuse code (should fail)
        self.assertFalse(
            self.auth_system.validate_verification_code(user['email'], code1),
            "Second validation of same code should fail"
        )

        # Test 3: Generate multiple codes for same user
        code2 = self.auth_system.generate_verification_code(user['email'])
        self.assertNotEqual(
            code1, code2,
            "Subsequent verification codes should be different"
        )

        # Test 4: Code expiration
        verification_data = self.auth_system.verification_codes[user['email']]
        verification_data['created_at'] -= timedelta(minutes=16)  # Simulate old code
        self.assertFalse(
            self.auth_system.validate_verification_code(user['email'], code2),
            "Expired verification code should be rejected"
        )

    def test_duplicate_registration_comprehensive(self):
        """Comprehensive test for duplicate registration prevention"""
        # First user registration
        user1 = self.generate_test_user('first')
        success, message = self.auth_system.register_user(
            user1['name'], user1['email'], user1['phone'], user1['password']
        )
        self.assertTrue(success, "First registration should succeed")

        # Scenarios to test
        duplicate_scenarios = [
            # Scenario 1: Exact same user details
            {
                'name': user1['name'],
                'email': user1['email'],
                'phone': user1['phone'],
                'password': user1['password'],
                'expected_message': "User already exists"
            },
            # Scenario 2: Same email, different other details
            {
                'name': "Different Name",
                'email': user1['email'],
                'phone': f"+1{secrets.randbelow(9000000000) + 1000000000}",
                'password': "DifferentPass123!",
                'expected_message': "User already exists"
            },
            # Scenario 3: Same phone, different other details
            {
                'name': "Another Different Name",
                'email': f"another_{secrets.token_hex(4)}@example.com",
                'phone': user1['phone'],
                'password': "AnotherDifferentPass123!",
                'expected_message': "User already exists"
            }
        ]

        # Test each duplicate registration scenario
        for scenario in duplicate_scenarios:
            with self.subTest(email=scenario['email'], phone=scenario['phone']):
                success, message = self.auth_system.register_user(
                    scenario['name'],
                    scenario['email'],
                    scenario['phone'],
                    scenario['password']
                )
                self.assertFalse(success, "Duplicate registration should fail")
                self.assertEqual(message, scenario['expected_message'])

    @classmethod
    def tearDownClass(cls):
        """Clean up test resources"""
        # Close database connection
        cls.db_manager.close()

        # Remove temporary database file
        try:
            os.remove(cls.temp_db_file)
        except Exception:
            pass


def main():
    """Run tests with detailed output"""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAuthenticationSystem)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with non-zero status if tests fail
    sys.exit(not result.wasSuccessful())


if __name__ == '__main__':
    main()