# Secure Password Manager

## Overview

This is a robust, secure desktop password manager built with Python and Tkinter, offering a user-friendly interface for securely storing and managing your passwords.

## Features

- 🔒 Strong encryption using Fernet symmetric encryption
- 👤 User authentication with secure password hashing
- ✨ Intuitive graphical user interface
- 🔍 Password search functionality
- 🔐 Ability to add, view, and delete passwords
- 🛡️ Secure password reset mechanism

## Prerequisites

- Python 3.8+
- tkinter
- cryptography
- ttkthemes
- sqlite3

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nethinduhansaka-dev/secure-password-manager.git
cd secure-password-manager
```

2. Install required dependencies:
```bash
pip install cryptography ttkthemes
```

## Running the Application

```bash
python password_manager.py
```

## Security Features

### Password Storage
- Passwords are encrypted using Fernet symmetric encryption
- User passwords are hashed using PBKDF2 with SHA-256
- Unique salt generated for each user

### Authentication
- Secure login mechanism
- Password reset functionality
- Protection against brute-force attacks

## How It Works

1. **First-time Setup**: Creates a new user account
2. **Login**: Authenticate with username and password
3. **Password Management**:
   - Add new passwords
   - View existing passwords
   - Delete passwords
   - Search through saved passwords

## Security Recommendations

- Use a strong master password
- Do not share your master password
- Keep the application and dependencies updated

## Limitations & Potential Improvements

- Add two-factor authentication
- Implement password strength checker
- Create export/import functionality
- Add automatic password generator

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Disclaimer

This password manager is for educational purposes. While efforts have been made to ensure security, it is recommended to use well-established password management solutions for critical data.

## Contact

Your Name - nethinduhansaka6113@gmail.com

Project Link: [https://github.com/nethinduhansaka-dev/secure-password-manager](https://github.com/nethinduhansaka-dev/secure-password-manager)
