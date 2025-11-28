# config file

RISK_THRESHOLDS = {
    'ip_address': 30,
    'insecure_scheme': 20,
    'at_symbol': 35, # fyi is our cred redirect attempt check
    'long_url': 10,
    'excessive_subdomains': 10,
    'suspicious_keywords': 10,
    'percent_encoding': 7,
    'multiple_hyphens': 5,
}

URL_ANALYSIS = {
    'max_length': 75,
    'min_subdomains_suspicious': 3,
    'min_hyphens_suspicious': 2,
}

VERDICT_THRESHOLDS = {
    'low': 30,
    'medium': 60,
    'high': 85,
}

# temp list of suspicious keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'secure', 'account', 'update', 'verify',
    'bank', 'confirm', 'password', 'ebay', 'paypal', 'appleid',
    'billing', 'wp-admin', 'auth', 'checkout'
]

# Flask app settings
FLASK = {
    'host': '127.0.0.1',
    'port': 5000,
    'debug': True,
}

# logging settings
LOGGING = {
    'max_bytes': 5 * 1024 * 1024,  # 5MB
    'backup_count': 5,
}

# rate limiting settings
RATE_LIMITING = {
    'enabled': True,
    'limit': '10 per minute',  # 10 requests per minute per IP
    'storage_url': 'memory://',  # Using in-memory storage (can switch to redis://)
}
