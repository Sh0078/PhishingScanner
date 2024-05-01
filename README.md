<img width="909" alt="Screenshot 2024-05-01 at 4 00 19 PM" src="https://github.com/Sh0078/PhishingScanner/assets/118327722/f09011a0-20a4-43f6-992c-c384189f1dac">

<img width="897" alt="Screenshot 2024-05-01 at 4 07 17 PM" src="https://github.com/Sh0078/PhishingScanner/assets/118327722/16fb1c51-1393-4fe9-a909-f2f0bcae8cdc">

# Phishing Email Scanner

This project is a Python-based email scanner designed to detect phishing emails in an IMAP mailbox. It checks for common phishing indicators, including suspicious subjects, malicious URLs, suspicious patterns, and excessive grammar errors. The scanner also validates email addresses to help identify potentially malicious senders.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

## Installation

To set up this project on your system, you'll need Python 3 and a few additional libraries. Follow these steps to install the necessary dependencies:

1. Clone the repository to your local machine:
   ```bash
   git clone <repository-url>
   cd <repository-folder>

2. Set up a virtual environment (optional but recommended):
```python3 -m venv venv source venv/bin/activate  # On Windows, use venv\Scripts\activate```

3. Install the required libraries using pip:
```pip install -r requirements.txt```


### Usage

To use the phishing email scanner, run the following command:

```python
python3 phishing_scanner.py --server <IMAP server> --username <email> --password <password>
```


Replace IMAP server, username, and password with your IMAP server address, email username, and password, not your email password but the application password, you can get this password after you enable your 2fac in security feature, and create new app password. You can also specify the mailbox to scan using the --mailbox option (default is inbox).


### Features

- Email Validation: Validates sender email addresses to detect invalid or potentially malicious addresses.
- Subject Analysis: Checks for common phishing-related keywords and suspicious patterns in the email subject.
- Body Analysis: Checks for phishing-related keywords, suspicious URLs, and excessive grammar errors in the email body.
- Grammar Checking: Uses language_tool_python to identify excessive grammar errors in email bodies.

### Dependencies

This project relies on several external libraries. The key dependencies are:

- imaplib: For IMAP email retrieval.
- email: For parsing email messages.
- re: For regular expressions.
- language_tool_python: For grammar checking.
- email_validator: For validating email addresses.

Ensure that all dependencies are installed using the requirements.txt file provided in the repository.

### Contributing

Contributions are welcome! If you would like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and ensure the code is tested.
4. Submit a pull request with a clear description of your changes.

### License

This project is licensed under the MIT License. See the LICENSE file for more details.
