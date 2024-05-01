import unittest
from email.message import EmailMessage
from phishing_scanner import (
    connect_to_mailbox,
    validate_email_address,
    get_email_body,
    extract_urls,
    check_grammar,
    is_malicious_url,
    is_phishing_email,
    scan_emails,
)

class TestPhishingScanner(unittest.TestCase):
    def setUp(self):
        # Prepare common test data
        self.valid_email = "valid@example.com"
        self.invalid_email = "invalid-email"

        # Create a basic email message with text content
        self.email_message = EmailMessage()
        self.email_message["From"] = self.valid_email
        self.email_message["Subject"] = "Test Subject"
        self.email_message.set_content("This is a test email body.")

        # Create a multipart email with HTML content
        self.multipart_email = EmailMessage()
        self.multipart_email.add_alternative(
            "<html><body>This is an HTML email body.</body></html>", subtype="html"
        )

    def test_connect_to_mailbox(self):
        # Test with valid credentials
        mail = connect_to_mailbox("imap.example.com", "user", "password")
        self.assertIsNotNone(mail)  # Ensure connection is successful

    def test_validate_email_address(self):
        # Test with valid email
        self.assertTrue(validate_email_address(self.valid_email))

        # Test with invalid email
        self.assertFalse(validate_email_address(self.invalid_email))

    def test_get_email_body(self):
        # Test with plain text email
        body = get_email_body(self.email_message)
        self.assertEqual(body.strip(), "This is a test email body.")

        # Test with multipart HTML email
        body_html = get_email_body(self.multipart_email).strip()
        self.assertEqual(body_html, "This is an HTML email body.")

    def test_extract_urls(self):
        # Test with text containing URLs
        text_with_urls = "Visit http://example.com and https://example.org for more info."
        urls = extract_urls(text_with_urls)
        self.assertEqual(len(urls), 2)
        self.assertIn("http://example.com", urls)
        self.assertIn("https://example.org", urls)

    def test_is_malicious_url(self):
        # Test with known URL shorteners
        self.assertTrue(is_malicious_url("http://bit.ly/12345"))

        # Test with safe URL
        self.assertFalse(is_malicious_url("https://example.com"))

    def test_check_grammar(self):
        # Test with a text containing grammar errors
        grammar_text = "This is a bad grammar example. It have mistakes."
        self.assertTrue(check_grammar(grammar_text))

        # Test with a grammatically correct text
        correct_text = "This is a correct sentence."
        self.assertFalse(check_grammar(correct_text))

    def test_is_phishing_email(self):
        # Test a non-phishing email
        self.assertFalse(is_phishing_email(self.email_message))

        # Test a phishing email with suspicious subject
        phishing_email = EmailMessage()
        phishing_email["From"] = self.valid_email
        phishing_email["Subject"] = "URGENT: Reset your password"
        phishing_email.set_content("Please reset your password.")
        self.assertTrue(is_phishing_email(phishing_email))  # Suspicious due to subject

        # Test a phishing email with malicious URL
        phishing_email.set_content("Check this link: http://bit.ly/12345")
        self.assertTrue(is_phishing_email(phishing_email))  # Suspicious due to malicious URL

    def test_scan_emails(self):
        # This would require a mock or a controlled environment
        mail = connect_to_mailbox("imap.example.com", "user", "password")
        phishing_emails = scan_emails(mail)
        self.assertIsInstance(phishing_emails, list)

if __name__ == "__main__":
    unittest.main()
