import re
import validators

# Define some simple suspicious patterns
suspicious_words = ["login", "verify", "account", "secure", "bank", "update"]
ip_pattern = r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"  # Pattern for IP-based URLs

# A function to check if the URL is valid and contains suspicious words
def is_phishing_link(url):
    # Check if the URL is valid
    if not validators.url(url):
        return "Invalid URL"
    
    # Check for suspicious words
    for word in suspicious_words:
        if word in url.lower():
            return "Phishing suspected: Suspicious word found"
    
    # Check for IP-based URLs (often used in phishing)
    if re.search(ip_pattern, url):
        return "Phishing suspected: IP-based URL"
    
    return "URL looks safe"

# Test the scanner with a few URLs
urls = [
    "https://secure-login.bank.com",
    "http://example.com",
    "http://192.168.0.1/login",
    "http://malicious-site.com-update.com"
]

for url in urls:
    result = is_phishing_link(url)
    print(f"URL: {url} -> {result}")