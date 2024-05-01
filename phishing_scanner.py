import argparse
import imaplib
import email
import re
import language_tool_python
from bs4 import BeautifulSoup
from email_validator import validate_email, EmailNotValidError


# Connect to IMAP Server and start Inbox scanning
def connect_to_mailbox(server, username, password):
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(username, password)
        return mail
    except imaplib.IMAP4.error as e:
        print(f"IMAP connection error: {str(e)}")
        return None

# Validate email address
def validate_email_address(email_address):
    try:
        validate_email(email_address, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

# Extract URLs from text
def extract_urls(text):
    return re.findall(r"http[s]?://[^\s]+", text)

def is_malicious_url(url):
    # Known URL shorteners
    url_shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "cutt.ly"]

    # Check if the URL uses a shortener
    for shortener in url_shorteners:
        if shortener in url:
            return True

    # Check for known suspicious patterns
    suspicious_patterns = [
        r".*login.*",  # URLs with "login" are potentially dangerous
        r".*password.*",  # URLs with "password"
        r".*reset.*",  # URLs with "reset"
        r".*verify.*",  # URLs with "verify"
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    return False

# Get email body
def get_email_body(email_message):
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            print(f"Content type: {content_type}")
            if content_type == "text/plain":
                try:
                    return part.get_payload(decode=True).decode("utf-8")
                except UnicodeDecodeError:
                    return part.get_payload(decode=True).decode("latin-1")
            elif content_type == "text/html":
                html_content = part.get_payload(decode=True)
                soup = BeautifulSoup(html_content, "html.parser")
                return soup.get_text()  # Extract text from HTML content
    else:
        return email_message.get_payload(decode=True).decode("utf-8")

# Check grammar in text
def check_grammar(text):
    try:
        tool = language_tool_python.LanguageTool("en-US")
        matches = tool.check(text)
        if len(matches) > 10:
            for match in matches:
                print(f"Grammar error at position {match.offset}: {match.message}")
            return True
        return False
    except Exception as e:
        print(f"Error during grammar check: {str(e)}")
        return False

# Determine if an email is phishing
def is_phishing_email(email_message):
    try:
        sender = email_message["From"]
        subject = email_message["Subject"]
        body = get_email_body(email_message)

        if not validate_email_address(sender):
            print("Invalid email address: ", sender)
            return True 
        else:
            print("valid email address: ", sender ) # Email is suspicious due to invalid sender

        # Check for urgency keywords in subject
        urgency_keywords = ["urgent", "reset", "password", "account", "login", "update", "change", "renew", "verify", "confirm"]
        if any(keyword in subject.lower() for keyword in urgency_keywords):
            print("Urgency keyword in subject: ", subject)
            return True  # Suspicious if urgency-related keywords found
        
        # Check for common financial terms in subject
        financial_keywords = ["invoice", "payment", "credit card", "transfer", "bank", "fee", "refund", "billing", "transaction"]
        if any(keyword in subject.lower() for keyword in financial_keywords):
            print("Financial keyword in subject: ", subject)
            return True
        
        # Check for suspicious patterns in subject
        suspicious_patterns = [
            r"free .+",
            r"claim your .+",
            r"congratulations .+",
            r"you have won .+",
            r"exclusive offer",
            r"no reply",
            r"\d+% off"
        ]
        if any(re.search(pattern, subject, re.IGNORECASE) for pattern in suspicious_patterns):
            print("Suspicious pattern in subject: ", subject)
            return True
        
        # Check for suspicious keywords in body
        if re.search(r"\bpassword\b|\blogin\b|\baccount\b|\bverify\b|\bconfirm\b|\bupdate\b", body, re.IGNORECASE):
            print("Suspicious keywords in body.")
            return True
        
        # Check for suspicious URLs
        urls = extract_urls(body)
        for url in urls:
            if is_malicious_url(url):
                print("Malicious url found in email body.")
                return True  # Found a malicious URL
            else:
                print("No Malicious url found in email body.")
        
        
        # Check for grammar errors
        if check_grammar(body):
            print("Grammar errors in email body.")
            return True
        else:
            print("No Grammer error found in email body.")

    except Exception as e:
        print("Error in determining phishing email: ", str(e))
        return True  # Assume phishing in case of unexpected error

# Scan for phishing emails in a given mailbox
def scan_emails(mail, mailbox="inbox"):
    try:
        mail.select(mailbox)
        result, data = mail.search(None, "UNSEEN")
        
        if result != "OK":
            raise Exception("Failed to retrieve email list")

        phishing_emails = []
        for num in data[0].split():
            result, data = mail.fetch(num, "(RFC822)")
            raw_email = data[0][1]
            email_message = email.message_from_bytes(raw_email)

            if is_phishing_email(email_message):
                phishing_emails.append(email_message)

        return phishing_emails
    
    except Exception as e:
        print(f"Error during email scan: {str(e)}")
        return []

def main(args):
    mail = connect_to_mailbox(args.server, args.username, args.password)
    
    if not mail:
        print("Failed to connect to mailbox")
        return

    phishing_emails = scan_emails(mail, args.mailbox)

    if not phishing_emails:
        print("No phishing emails detected.")
    else:
        for email_message in phishing_emails:
            print("Phishing Email Detected:")
            print("From: ", email_message["From"])
            print("Subject: ", email_message["Subject"])
            print("Body: ", get_email_body(email_message))
            print("=" * 50)

    mail.logout()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Email Scanner")
    parser.add_argument("--server", required=True, help="IMAP server address")
    parser.add_argument("--username", required=True, help="Email username")
    parser.add_argument("--password", required=True, help="Email password")
    parser.add_argument("--mailbox", default="inbox", help="Mailbox to scan")
    
    args = parser.parse_args()
    main(args)