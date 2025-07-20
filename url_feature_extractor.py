import re
import urllib.parse
from urllib.parse import urlparse
import math
from collections import Counter

def extract_features(url):
    """
    Extract features from a URL for phishing detection.
    Returns a dictionary with feature names matching the dataset columns.
    """
    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
        
        # Initialize features dictionary
        features = {}
        
        # URL length features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        
        # Count various characters in URL
        features['number_of_dots_in_url'] = url.count('.')
        features['number_of_hyphens_in_url'] = url.count('-')
        features['number_of_underline_in_url'] = url.count('_')
        features['number_of_slash_in_url'] = url.count('/')
        features['number_of_questionmark_in_url'] = url.count('?')
        features['number_of_equal_in_url'] = url.count('=')
        features['number_of_at_in_url'] = url.count('@')
        features['number_of_dollar_in_url'] = url.count('$')
        features['number_of_exclamation_in_url'] = url.count('!')
        features['number_of_hashtag_in_url'] = url.count('#')
        features['number_of_percent_in_url'] = url.count('%')
        
        # Count digits in URL
        digits_in_url = sum(1 for char in url if char.isdigit())
        features['number_of_digits_in_url'] = digits_in_url
        
        # Check for repeated digits
        digit_chars = [char for char in url if char.isdigit()]
        repeated_digits = any(digit_chars.count(digit) > 1 for digit in set(digit_chars))
        features['having_repeated_digits_in_url'] = 1 if repeated_digits else 0
        
        # Count special characters (excluding alphanumeric, dots, hyphens, slashes)
        special_chars = re.findall(r'[^a-zA-Z0-9.\-/]', url)
        features['number_of_special_char_in_url'] = len(special_chars)
        
        # Domain features
        features['number_of_dots_in_domain'] = domain.count('.')
        features['number_of_hyphens_in_domain'] = domain.count('-')
        
        # Check for special characters in domain
        domain_special_chars = re.findall(r'[^a-zA-Z0-9.\-]', domain)
        features['having_special_characters_in_domain'] = 1 if domain_special_chars else 0
        features['number_of_special_characters_in_domain'] = len(domain_special_chars)
        
        # Check for digits in domain
        domain_digits = sum(1 for char in domain if char.isdigit())
        features['having_digits_in_domain'] = 1 if domain_digits > 0 else 0
        features['number_of_digits_in_domain'] = domain_digits
        
        # Check for repeated digits in domain
        domain_digit_chars = [char for char in domain if char.isdigit()]
        domain_repeated_digits = any(domain_digit_chars.count(digit) > 1 for digit in set(domain_digit_chars))
        features['having_repeated_digits_in_domain'] = 1 if domain_repeated_digits else 0
        
        # Subdomain features
        subdomains = domain.split('.')
        features['number_of_subdomains'] = len(subdomains)
        
        # Check subdomain characteristics
        features['having_dot_in_subdomain'] = 0  # By definition, subdomains don't contain dots
        features['having_hyphen_in_subdomain'] = 1 if any('-' in sub for sub in subdomains) else 0
        
        # Average subdomain length
        if subdomains:
            features['average_subdomain_length'] = sum(len(sub) for sub in subdomains) / len(subdomains)
        else:
            features['average_subdomain_length'] = 0
        
        # Average dots and hyphens in subdomains
        features['average_number_of_dots_in_subdomain'] = 0.0  # By definition
        total_hyphens = sum(sub.count('-') for sub in subdomains)
        features['average_number_of_hyphens_in_subdomain'] = total_hyphens / len(subdomains) if subdomains else 0
        
        # Special characters in subdomains
        subdomain_special_chars = 0
        subdomain_digits = 0
        subdomain_repeated_digits = False
        
        for sub in subdomains:
            subdomain_special_chars += len(re.findall(r'[^a-zA-Z0-9\-]', sub))
            sub_digits = sum(1 for char in sub if char.isdigit())
            subdomain_digits += sub_digits
            
            sub_digit_chars = [char for char in sub if char.isdigit()]
            if any(sub_digit_chars.count(digit) > 1 for digit in set(sub_digit_chars)):
                subdomain_repeated_digits = True
        
        features['having_special_characters_in_subdomain'] = 1 if subdomain_special_chars > 0 else 0
        features['number_of_special_characters_in_subdomain'] = subdomain_special_chars
        features['having_digits_in_subdomain'] = 1 if subdomain_digits > 0 else 0
        features['number_of_digits_in_subdomain'] = subdomain_digits
        features['having_repeated_digits_in_subdomain'] = 1 if subdomain_repeated_digits else 0
        
        # Path, query, fragment features
        features['having_path'] = 1 if path and path != '/' else 0
        features['having_query'] = 1 if query else 0
        features['having_fragment'] = 1 if fragment else 0
        features['having_anchor'] = 1 if '#' in url else 0
        
        # Entropy calculation
        def calculate_entropy(text):
            if not text:
                return 0
            counter = Counter(text)
            length = len(text)
            entropy = 0
            for count in counter.values():
                p = count / length
                entropy -= p * math.log2(p)
            return entropy
        
        features['entropy_of_url'] = calculate_entropy(url)
        features['entropy_of_domain'] = calculate_entropy(domain)
        
        return features
        
    except Exception as e:
        # If URL parsing fails, return default values
        return {
            'url_length': 0, 'number_of_dots_in_url': 0, 'having_repeated_digits_in_url': 0,
            'number_of_digits_in_url': 0, 'number_of_special_char_in_url': 0,
            'number_of_hyphens_in_url': 0, 'number_of_underline_in_url': 0,
            'number_of_slash_in_url': 0, 'number_of_questionmark_in_url': 0,
            'number_of_equal_in_url': 0, 'number_of_at_in_url': 0,
            'number_of_dollar_in_url': 0, 'number_of_exclamation_in_url': 0,
            'number_of_hashtag_in_url': 0, 'number_of_percent_in_url': 0,
            'domain_length': 0, 'number_of_dots_in_domain': 0,
            'number_of_hyphens_in_domain': 0, 'having_special_characters_in_domain': 0,
            'number_of_special_characters_in_domain': 0, 'having_digits_in_domain': 0,
            'number_of_digits_in_domain': 0, 'having_repeated_digits_in_domain': 0,
            'number_of_subdomains': 0, 'having_dot_in_subdomain': 0,
            'having_hyphen_in_subdomain': 0, 'average_subdomain_length': 0,
            'average_number_of_dots_in_subdomain': 0, 'average_number_of_hyphens_in_subdomain': 0,
            'having_special_characters_in_subdomain': 0, 'number_of_special_characters_in_subdomain': 0,
            'having_digits_in_subdomain': 0, 'number_of_digits_in_subdomain': 0,
            'having_repeated_digits_in_subdomain': 0, 'having_path': 0,
            'path_length': 0, 'having_query': 0, 'having_fragment': 0,
            'having_anchor': 0, 'entropy_of_url': 0, 'entropy_of_domain': 0
        }