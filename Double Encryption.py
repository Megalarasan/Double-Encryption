from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class DoubleEncryption:
    def __init__(self, password):
        """
        Initialize the DoubleEncryption object with the password.
        :param password: The password to be double encrypted.
        """
        self._password = password
        self._salt = self._generate_salt()

    def _generate_key(self):
        """
        Generate a key from the password and salt using PBKDF2HMAC algorithm.
        :return: The derived key.
        """
        password = self._password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def _generate_salt(self):
        """
        Generate a random salt.
        :return: The generated salt.
        """
        return base64.urlsafe_b64encode(os.urandom(16))

    def _encrypt_password(self, password):
        """
        Encrypt the password using Fernet encryption.
        :param password: The password to be encrypted.
        :return: The encrypted password.
        """
        key = self._generate_key()
        f = Fernet(key)
        encrypted_password = f.encrypt(password.encode())
        return encrypted_password

    def calculate_password_strength(self, min_password_length=8):
        """
        Calculate the strength of the password based on its length and complexity.
        :param min_password_length: The minimum length required for a strong password.
        :return: The strength of the password (0-4).
        """
        length = len(self._password)
        if length < min_password_length:
            return 0

        has_uppercase = any(char.isupper() for char in self._password)
        has_lowercase = any(char.islower() for char in self._password)
        has_symbol = any(char in "!@#$%^&*()-_=+[]{};:'\"|,.<>/?`~" for char in self._password)
        has_number = any(char.isdigit() for char in self._password)

        if has_uppercase and has_lowercase and has_symbol and has_number:
            return 4
        elif length < min_password_length + 3:
            return 1
        elif length < min_password_length + 6:
            return 2
        elif length < min_password_length + 9:
            return 3
        else:
            return 4

    def double_encrypt_password(self):
        """
        Perform double encryption on the password.
        :return: The double encrypted password.
        """
        encrypted_password = self._encrypt_password(self._password)
        double_encrypted_password = self._encrypt_password(encrypted_password.decode())
        return double_encrypted_password

    def decrypt_password(self, encrypted_password):
        """
        Decrypt the password using Fernet decryption.
        :param encrypted_password: The encrypted password to be decrypted.
        :return: The decrypted password.
        """
        key = self._generate_key()
        f = Fernet(key)
        decrypted_password = f.decrypt(encrypted_password)
        return decrypted_password.decode()

# Example usage
password = input("Enter Your Password:");
double_encryptor = DoubleEncryption(password)
encrypted_password = double_encryptor.double_encrypt_password()
strength = double_encryptor.calculate_password_strength()

print("Double Encrypted Password:", encrypted_password)
print("Password Strength (0-4):", strength)
