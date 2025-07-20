#!/usr/bin/env python3
"""
Enhanced Working Phishing Detection Demo with Advanced Corner Case Detection
"""

import pandas as pd
import joblib
from url_feature_extractor import extract_features
from urllib.parse import urlparse
import unicodedata

#!/usr/bin/env python3
"""
Enhanced Working Phishing Detection Demo with Advanced Corner Case Detection
"""

import pandas as pd
import joblib
from url_feature_extractor import extract_features
from urllib.parse import urlparse
import unicodedata

# Load model and scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

# Load feature column order
feature_columns = pd.read_csv("feature_columns.csv", header=None).squeeze().tolist()

# Enhanced whitelist with exact domain matching
WHITELISTED_DOMAINS = {
    "google.com", "whatsapp.com", "microsoft.com", "facebook.com", "apple.com",
    "instagram.com", "linkedin.com", "amazon.com", "youtube.com", "github.com",
    "paypal.com", "dropbox.com", "twitter.com", "netflix.com", "spotify.com",
    "slack.com", "zoom.us", "skype.com", "discord.com", "reddit.com"
}

# Brand keywords for typosquatting detection
BRAND_KEYWORDS = {
    "google", "facebook", "apple", "microsoft", "amazon", "paypal", "netflix",
    "instagram", "linkedin", "twitter", "github", "dropbox", "spotify", "slack",
    "whatsapp", "youtube", "zoom", "skype", "discord", "reddit", "ebay"
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".download", 
    ".work", ".review", ".shop", ".tech", ".xyz", ".club", ".online", 
    ".site", ".website", ".space", ".info", ".biz"
}

# Suspicious keywords
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "secure", "verify", "update", "confirm", "account",
    "banking", "payment", "billing", "suspended", "limited", "urgent"
}

def is_whitelisted(url):
    """Check if URL is from a whitelisted domain - exact match only"""
    domain = urlparse(url).netloc.lower()
    domain = domain.replace('www.', '')
    return domain in WHITELISTED_DOMAINS

def detect_advanced_risks(url):
    """Detect advanced phishing risks"""
    risks = []
    risk_score = 0
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # 1. Check for brand names in subdomain with different main domain
    if '.' in domain:
        parts = domain.split('.')
        if len(parts) >= 3:  # Has subdomain
            subdomain = '.'.join(parts[:-2])
            main_domain = parts[-2]
            
            for brand in BRAND_KEYWORDS:
                if brand in subdomain and brand != main_domain:
                    risks.append(f"Brand '{brand}' in subdomain with different main domain")
                    risk_score += 15
    
    # 2. Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            risks.append(f"Suspicious TLD '{tld}' detected")
            risk_score += 8
            break
    
    # 3. Check for suspicious keywords in domain
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            risks.append(f"Suspicious keyword '{keyword}' in domain")
            risk_score += 5
    
    # 4. Check for homograph attacks (non-ASCII characters)
    if not domain.isascii():
        risks.append("Non-ASCII characters detected (possible homograph attack)")
        risk_score += 10
    
    # 5. Check for excessive subdomain levels
    subdomain_levels = domain.count('.')
    if subdomain_levels > 3:
        risks.append(f"Excessive subdomain levels: {subdomain_levels}")
        risk_score += 6
    
    # 6. Check for suspicious path patterns
    suspicious_paths = ["login", "signin", "verify", "secure", "update", "confirm"]
    for sus_path in suspicious_paths:
        if sus_path in path:
            risks.append(f"Suspicious path pattern: {sus_path}")
            risk_score += 3
    
    return risks, risk_score

def normalize_url(url):
    """Normalize URL by adding protocol if missing"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def predict_with_comprehensive_analysis(url):
    """Enhanced prediction with advanced risk detection"""
    try:
        # Normalize URL first
        normalized_url = normalize_url(url)
        
        # Check whitelist first
        if is_whitelisted(normalized_url):
            return "✅ LEGITIMATE (WHITELISTED)", 0.01, [], {}
        
        # Detect advanced risks
        risk_details, risk_score = detect_advanced_risks(normalized_url)
        
        # Extract standard features
        features = extract_features(normalized_url)
        
        # Prepare DataFrame in correct order
        ordered_features = [features.get(col, 0) for col in feature_columns]
        df = pd.DataFrame([ordered_features], columns=feature_columns)
        
        # Scale and predict
        df_scaled = scaler.transform(df)
        ml_probability = model.predict_proba(df_scaled)[0][1]
        
        # Combine ML prediction with advanced risk
        risk_adjustment = min(risk_score * 0.05, 0.4)  # Max 40% adjustment
        final_probability = min(ml_probability + risk_adjustment, 1.0)
        
        # Determine result based on enhanced thresholds
        if final_probability >= 0.7 or risk_score >= 15:
            result = "🚨 PHISHING"
        elif final_probability >= 0.4 or risk_score >= 8:
            result = "⚠️ SUSPICIOUS"
        else:
            result = "✅ LEGITIMATE"
        
        return result, final_probability, risk_details, features
        
    except Exception as e:
        return f"❌ Error: {str(e)}", 0.0, [], {}

def main():
    """Enhanced main demo function with advanced detection"""
    print("🛡️  ADVANCED PHISHING DETECTION DEMO")
    print("=" * 80)
    
    # Enhanced test URLs including corner cases
    sample_urls = [
        # Legitimate sites
        "https://www.google.com",
        "https://github.com/microsoft/vscode",
        "https://www.paypal.com/signin",
        
        # Original sophisticated examples
        "https://signin-apple.com",
        "https://dropbox.com.getstorage.app",
        "https://www.linkedin.com-login-page-review.com",
        
        # IDN/Homograph attacks
        "https://xn--googl-fsa.com",  # googłe.com
        "https://аpple.com",  # Cyrillic 'а'
        "https://www.googIe.com",  # Capital I instead of l
        
        # Trusted platform abuse
        "https://drive.google.com/file/d/123/phishing-login.html",
        "https://storage.googleapis.com/bucket/secure-login.html",
        
        # Misleading subdomains
        "https://paypal.com.login.verify.secure-banking-portal.net",
        "https://amazon.com.account-verification.secure-update.tk",
        
        # Clean structure phishing
        "https://account-login.com",
        "https://secureupdate.shop",
        "https://bankportal.tech",
        "https://loginverify.xyz",
        
        # Traditional phishing
        "http://phishing-site-123.com/login.php?redirect=bank.com",
        "https://192.168.1.1/admin/login"
    ]
    
    print("🧪 TESTING SAMPLE URLs WITH ADVANCED DETECTION:")
    for url in sample_urls:
        analyze_url_advanced(url)
    
    print(f"\n{'='*80}")
    print("🔗 INTERACTIVE MODE - Enter your own URLs to test")
    print("   (Type 'quit' to exit)")
    print(f"{'='*80}")
    
    while True:
        user_url = input("\nEnter URL: ").strip()
        
        if user_url.lower() in ['quit', 'exit', 'q']:
            print("� Goodbye!")
            break
            
        if not user_url:
            continue
            
        # Add https:// if not present
        if not user_url.startswith(('http://', 'https://')):
            user_url = 'https://' + user_url
            
        analyze_url_advanced(user_url)

def analyze_url_advanced(url):
    """Analyze a single URL with advanced detection"""
    print(f"\n{'='*80}")
    print(f"🔍 ANALYZING: {url}")
    print(f"{'='*80}")
    
    result, probability, risk_details, features = predict_with_comprehensive_analysis(url)
    
    print(f"📊 PREDICTION: {result}")
    print(f"📈 FINAL PROBABILITY: {probability:.1%}")
    
    # Show risk level
    if probability >= 0.7:
        print("🚨 RISK LEVEL: HIGH")
    elif probability >= 0.4:
        print("⚠️ RISK LEVEL: MEDIUM")
    else:
        print("✅ RISK LEVEL: LOW")
    
    # Show advanced risk factors
    if risk_details:
        print(f"\n🚨 ADVANCED RISK FACTORS:")
        for detail in risk_details:
            print(f"   • {detail}")
    
    # Show features if not whitelisted
    if features:
        print(f"\n🔧 KEY FEATURES:")
        print(f"   • URL Length: {features.get('url_length', 0)} characters")
        print(f"   • Domain Length: {features.get('domain_length', 0)} characters")
        print(f"   • Special Characters: {features.get('number_of_special_char_in_url', 0)}")
        print(f"   • Dots in URL: {features.get('number_of_dots_in_url', 0)}")
        print(f"   • Hyphens in URL: {features.get('number_of_hyphens_in_url', 0)}")
        print(f"   • URL Entropy: {features.get('entropy_of_url', 0):.2f}")
        print(f"   • Domain Entropy: {features.get('entropy_of_domain', 0):.2f}")
    else:
        print(f"\n✅ Domain is in whitelist - automatically classified as legitimate")

if __name__ == "__main__":
    main()


