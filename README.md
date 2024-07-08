**DoubleEncryption Project**
Welcome to the DoubleEncryption Project! This project showcases a robust method for securing passwords using double encryption. It employs the cryptography library to achieve high levels of security.

**Overview**
The DoubleEncryption class provides functionalities to:

Generate a cryptographic key from a password and salt using the PBKDF2HMAC algorithm.
Encrypt a password twice to enhance security.
Calculate the strength of a password based on its length and complexity.
**Features**
Key Generation: Uses PBKDF2HMAC with SHA256, salt, and multiple iterations to generate a secure key.
Double Encryption: Encrypts the password twice using the Fernet symmetric encryption.
Password Strength Calculation: Evaluates password strength based on length, presence of uppercase and lowercase letters, numbers, and symbols.
