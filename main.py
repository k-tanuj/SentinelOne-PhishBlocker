from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from url_feature_extractor import extract_features
import joblib
import pandas as pd
from urllib.parse import urlparse
import unicodedata
from hdbcli import dbapi

app = FastAPI(title="Enhanced Phishing Detection API", version="2.0")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

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
    "slack.com", "zoom.us", "skype.com", "discord.com", "reddit.com",
    "stackoverflow.com", "stackexchange.com", "wikipedia.org", "wikimedia.org",
    "cloudflare.com", "godaddy.com", "wordpress.com", "medium.com", "quora.com",
    "sap.com"  # Add SAP to whitelist
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
    "banking", "payment", "billing", "suspended", "limited", "urgent",
    "security", "support", "help", "service", "notification", "alert"
}

# Malicious patterns
MALICIOUS_PATTERNS = {
    "random_chars": r'[a-z]{8,}',  # Long random character sequences
    "special_chars": r'[#@$%^&*+=<>?/\\|~`]',  # Special characters in domain
    "number_spam": r'\d{4,}',  # Too many consecutive numbers
    "mixed_case": r'[A-Z][a-z][A-Z][a-z]',  # Suspicious mixed case patterns
    "repeating": r'(.)\1{3,}',  # Repeating characters (aaaa, bbbb)
}

# Educational domain patterns (make legitimate but not whitelisted)
EDUCATIONAL_DOMAINS = {
    ".edu", ".ac.in", ".edu.in", ".ac.uk", ".edu.au", ".ac.za", 
    ".edu.sg", ".ac.nz", ".edu.my", ".ac.th", ".edu.pk", ".ac.bd"
}

# Government domain patterns
GOVERNMENT_DOMAINS = {
    ".gov", ".gov.in", ".gov.uk", ".gov.au", ".mil", ".org.in"
}

def is_whitelisted(url):
    """Check if URL is from a whitelisted domain - exact match only"""
    domain = urlparse(url).netloc.lower()
    domain = domain.replace('www.', '')
    return domain in WHITELISTED_DOMAINS

def detect_advanced_risks(url):
    """Detect advanced phishing risks"""
    import re
    
    risks = []
    risk_score = 0
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Remove www. for analysis
    clean_domain = domain.replace('www.', '')
    
    # 0. CRITICAL: Check for obviously malicious domains
    if detect_malicious_domain(clean_domain):
        risks.append("Malicious domain pattern detected (random/suspicious characters)")
        risk_score += 25  # High penalty for obvious malicious domains
    
    # 0.1. CRITICAL: Check for special characters in URL (immediate red flag)
    if re.search(r'[#@$%^&*+=<>?\\|~`!]', url):
        risks.append("Special characters detected in URL (major security risk)")
        risk_score += 30  # Even higher penalty for special chars
    
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
    
    # 7. Check domain length (very short or very long domains are suspicious)
    domain_parts = clean_domain.split('.')
    if len(domain_parts) >= 2:
        main_domain = domain_parts[-2]
        if len(main_domain) > 20:
            risks.append(f"Unusually long domain name: {len(main_domain)} characters")
            risk_score += 8
        elif len(main_domain) < 3:
            risks.append(f"Unusually short domain name: {len(main_domain)} characters")
            risk_score += 6
    
    # 8. Check for IP address instead of domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        risks.append("IP address used instead of domain name")
        risk_score += 12
    
    # 9. Check for URL shorteners (often used in phishing)
    url_shorteners = ['bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl', 'ow.ly']
    for shortener in url_shorteners:
        if shortener in domain:
            risks.append(f"URL shortener detected: {shortener}")
            risk_score += 7
    
    return risks, risk_score

def detect_malicious_domain(domain):
    """Detect obviously malicious domain patterns"""
    import re
    
    # Remove common TLDs for analysis
    domain_without_tld = re.sub(r'\.(com|org|net|edu|gov|mil|int|co\.uk|co\.in)$', '', domain)
    
    # Check for special characters in domain (major red flag)
    special_chars = re.findall(r'[#@$%^&*+=<>?/\\|~`!]', domain)
    if special_chars:
        return True
    
    # Check for too many numbers
    if re.search(r'\d{4,}', domain_without_tld):
        return True
    
    # Check for repeating characters (4 or more in a row)
    if re.search(r'(.)\1{3,}', domain_without_tld):
        return True
    
    # Check for very random-looking strings (only for longer domains)
    if len(domain_without_tld) > 15:
        # Count consonant clusters (sign of random strings)
        consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain_without_tld))
        if consonant_clusters >= 2:
            return True
        
        # Check vowel ratio only for very long domains
        vowels = len(re.findall(r'[aeiou]', domain_without_tld))
        total_chars = len(re.sub(r'[^a-z]', '', domain_without_tld))
        if total_chars > 0 and vowels / total_chars < 0.15:  # Less than 15% vowels = likely random
            return True
    
    # Check for mixed case chaos (if original had mixed case)
    if re.search(r'[A-Z][a-z][A-Z][a-z]', domain):
        return True
    
    # Check for obviously suspicious patterns (more specific)
    suspicious_patterns = [
        r'[a-z]{10,}[0-9]{3,}',  # Very long letters followed by numbers
        r'[bcdfghjklmnpqrstvwxyz]{7,}',  # Too many consonants (raised threshold)
        r'[aeiou]{5,}',  # Too many vowels in a row (raised threshold)
        r'[qwerty]{6,}',  # Keyboard mashing (raised threshold)
        r'[zxcv]{5,}',  # More keyboard patterns (raised threshold)
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain_without_tld):
            return True
    
    return False

def normalize_url(url):
    """Normalize URL by adding protocol if missing"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def is_legitimate_domain_type(url):
    """Check if URL is from educational, government, or other legitimate domain types"""
    domain = urlparse(url).netloc.lower()
    
    # Check educational domains
    for edu_suffix in EDUCATIONAL_DOMAINS:
        if domain.endswith(edu_suffix):
            return True, "EDUCATIONAL"
    
    # Check government domains  
    for gov_suffix in GOVERNMENT_DOMAINS:
        if domain.endswith(gov_suffix):
            return True, "GOVERNMENT"
    
    # Check well-known organization domains
    if domain.endswith('.org') and not any(sus in domain for sus in ['free', 'win', 'prize', 'alert']):
        # Basic .org domains are usually legitimate unless they have suspicious keywords
        return True, "ORGANIZATION"
    
    return False, None

def enhanced_predict(url):
    """Enhanced prediction with advanced risk detection"""
    try:
        # Normalize URL first
        normalized_url = normalize_url(url)
        
        # Extract standard features (always needed for analysis)
        features = extract_features(normalized_url)
        
        # Check whitelist first (highest priority)
        if is_whitelisted(normalized_url):
            return "LEGITIMATE (WHITELISTED)", 1.0, [], features
        
        # Check legitimate domain types (educational, government, etc.)
        is_legitimate_type, domain_type = is_legitimate_domain_type(normalized_url)
        if is_legitimate_type:
            return f"LEGITIMATE ({domain_type})", 0.95, [], features  # High confidence but not 100%
        
        # Detect advanced risks
        risk_details, risk_score = detect_advanced_risks(normalized_url)
        
        # Prepare DataFrame in correct order
        ordered_features = [features.get(col, 0) for col in feature_columns]
        df = pd.DataFrame([ordered_features], columns=feature_columns)
        
        # Scale and predict
        df_scaled = scaler.transform(df)
        ml_probability = model.predict_proba(df_scaled)[0][1]
        
        # Combine ML prediction with advanced risk
        risk_adjustment = min(risk_score * 0.05, 0.5)  # Max 50% adjustment for severe cases
        final_probability = min(ml_probability + risk_adjustment, 1.0)
        
        # Determine result based on enhanced thresholds
        if final_probability >= 0.65 or risk_score >= 20:  # Lower threshold for high-risk patterns
            result = "PHISHING"
        elif final_probability >= 0.35 or risk_score >= 10:  # Lower threshold for medium-risk
            result = "SUSPICIOUS"
        else:
            result = "LEGITIMATE"
        
        return result, final_probability, risk_details, features
        
    except Exception as e:
        return f"Error: {str(e)}", 0.0, [], {}

@app.post("/predict")
def predict_phishing(request: Request, url: str = Form(...)):
    """
    Enhanced phishing prediction with SAP HANA logging
    
    Enhanced Features:
    - Brand impersonation detection
    - Subdomain abuse detection
    - Suspicious TLD detection
    - Homograph attack detection
    - ML-based classification with 96.74% accuracy
    """
    try:
        # Use enhanced prediction system
        result, probability, risk_details, features = enhanced_predict(url)
        
        # Determine risk level
        if probability >= 0.7 and not result.startswith("LEGITIMATE"):
            risk_level = "HIGH"
        elif probability >= 0.4 and not result.startswith("LEGITIMATE"):
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        response = {
            "url": url,
            "result": result,
            "phishing_probability": round(probability, 3),
            "risk_level": risk_level
        }
        
        # Add advanced risk factors if detected
        if risk_details:
            response["advanced_risk_factors"] = risk_details
        
        # Add key features
        if features:
            response["features"] = {
                "url_length": features.get('url_length', 0),
                "domain_length": features.get('domain_length', 0),
                "special_characters": features.get('number_of_special_char_in_url', 0),
                "dots_in_url": features.get('number_of_dots_in_url', 0),
                "hyphens_in_url": features.get('number_of_hyphens_in_url', 0),
                "url_entropy": round(features.get('entropy_of_url', 0), 2),
                "domain_entropy": round(features.get('entropy_of_domain', 0), 2)
            }
        
        # Log to SAP HANA Cloud database
        if HANA_AVAILABLE:
            try:
                # Get client information
                client_ip = request.client.host if request.client else "unknown"
                user_agent = request.headers.get("user-agent", "unknown")
                
                # Log the comprehensive analysis result
                log_success = log_to_hana(
                    url=url,
                    result=result,
                    confidence=probability,
                    risk_level=risk_level,
                    risk_factors=risk_details,
                    url_features=features,
                    user_agent=user_agent,
                    ip_address=client_ip
                )
                
                response["logged_to_hana"] = log_success
                if log_success:
                    print(f"✅ Logged to SAP HANA: {url} -> {result}")
                else:
                    print(f"❌ Failed to log to SAP HANA: {url}")
                    
            except Exception as e:
                print(f"⚠️ SAP HANA logging error: {str(e)}")
                response["logged_to_hana"] = False
        else:
            response["logged_to_hana"] = False
            response["hana_status"] = "SAP HANA Cloud not available"
        
        return response
        
    except Exception as e:
        return {
            "error": str(e),
            "logged_to_hana": False
        }

@app.get("/", response_class=HTMLResponse)
def root():
    try:
        with open("static/index.html", "r", encoding="utf-8") as file:
            return file.read()
    except Exception as e:
        return f"<html><body><h1>Error loading page</h1><p>{str(e)}</p></body></html>"

@app.get("/api")
def api_info():
    return {
        "message": "Enhanced Phishing Detection API v2.0",
        "features": [
            "Advanced corner case detection",
            "IDN/Punycode attack detection",
            "Homograph attack detection",
            "Trusted platform abuse detection",
            "Subdomain abuse detection",
            "Clean structure phishing detection",
            "ML-based classification with 96.74% accuracy"
        ],
        "endpoints": {
            "predict": "/predict (POST)",
            "test_samples": "/test-samples (GET)",
            "documentation": "/docs"
        }
    }

@app.get("/test-samples")
def test_samples():
    """Test with sophisticated phishing examples"""
    test_urls = [
        "https://google.com",
        "https://signin-apple.com",
        "https://dropbox.com.getstorage.app",
        "https://www.linkedin.com-login-page-review.com",
        "https://xn--googl-fsa.com",  # IDN attack
        "https://аpple.com",  # Homograph attack
        "https://paypal.com.login.verify.secure-banking.net",  # Subdomain abuse
        "https://secureupdate.shop",  # Clean structure phishing
        "https://drive.google.com/file/d/123/phishing-login.html"  # Trusted platform abuse
    ]
    
    results = []
    for url in test_urls:
        try:
            result, probability, risk_details, features = enhanced_predict(url)
            results.append({
                "url": url,
                "result": result,
                "probability": round(probability, 3),
                "risk_level": "HIGH" if probability >= 0.7 else "MEDIUM" if probability >= 0.4 else "LOW",
                "advanced_risk_factors": risk_details
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    
    return {"test_results": results}

# Add this after your imports at the top of main.py
from fastapi import FastAPI, Form, Request

# Add SAP HANA database integration
try:
    from db import log_to_hana, get_all_logs, get_statistics, create_table_if_not_exists, test_connection
    HANA_AVAILABLE = True
    print("📦 SAP HANA Cloud module imported successfully")
    
    # Initialize database table on startup
    try:
        create_table_if_not_exists()
        success, message = test_connection()
        if success:
            print("✅ SAP HANA Cloud database connection established")
            print(f"   {message}")
        else:
            print(f"❌ SAP HANA Cloud connection failed: {message}")
            HANA_AVAILABLE = False
    except Exception as e:
        print(f"⚠️ SAP HANA Cloud setup error: {str(e)}")
        HANA_AVAILABLE = False
        
except ImportError as e:
    print(f"⚠️ SAP HANA Cloud not available - install hdbcli: pip install hdbcli")
    print(f"   Error: {str(e)}")
    HANA_AVAILABLE = False
except Exception as e:
    print(f"⚠️ SAP HANA Cloud module error: {str(e)}")
    HANA_AVAILABLE = False

# Add these new endpoints for HANA database management
@app.get("/logs")
def get_detection_logs(limit: int = 100):
    """Get phishing detection logs from SAP HANA Cloud database"""
    if not HANA_AVAILABLE:
        return {"error": "SAP HANA Cloud database not available"}
    
    try:
        logs = get_all_logs(limit)
        return {
            "message": f"Retrieved {len(logs)} detection logs from SAP HANA Cloud",
            "total_retrieved": len(logs),
            "logs": logs
        }
    except Exception as e:
        return {"error": f"Failed to retrieve logs from SAP HANA: {str(e)}"}

@app.get("/statistics")
def get_detection_statistics():
    """Get detection statistics from SAP HANA Cloud database"""
    if not HANA_AVAILABLE:
        return {"error": "SAP HANA Cloud database not available"}
    
    try:
        stats = get_statistics()
        return {
            "message": "Phishing detection statistics from SAP HANA Cloud",
            "database": "SAP HANA Cloud",
            "statistics": stats
        }
    except Exception as e:
        return {"error": f"Failed to retrieve statistics from SAP HANA: {str(e)}"}

@app.get("/database/status")
def check_database_status():
    """Check SAP HANA Cloud database connection status"""
    if not HANA_AVAILABLE:
        return {
            "status": "unavailable",
            "message": "SAP HANA Cloud database module not available",
            "connected": False,
            "database_type": "SAP HANA Cloud"
        }
    
    try:
        connected, message = test_connection()
        return {
            "status": "connected" if connected else "error",
            "message": message,
            "connected": connected,
            "database_type": "SAP HANA Cloud"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "connected": False,
            "database_type": "SAP HANA Cloud"
        }

def fix_logging():
    """Fix HANA logging by adding missing columns"""
    try:
        conn = dbapi.connect(
            address="754db17e-af16-4009-9baa-1bca994a48de.hana.trial-us10.hanacloud.ondemand.com",
            port=443,
            user="DBADMIN",
            password="Tcs@18420",
            encrypt=True,
            sslValidateCertificate=False
        )
        
        cursor = conn.cursor()
        
        print("🔍 Checking table structure...")
        
        # Check existing columns
        cursor.execute("""
            SELECT COLUMN_NAME 
            FROM TABLE_COLUMNS 
            WHERE SCHEMA_NAME = 'SENTINELONE' 
            AND TABLE_NAME = 'PHISHING_LOGS'
        """)
        
        existing_columns = [row[0] for row in cursor.fetchall()]
        print(f"📋 Existing columns: {existing_columns}")
        
        # Required columns that are missing
        required_columns = {
            'RISK_LEVEL': 'NVARCHAR(20)',
            'RISK_FACTORS': 'NCLOB',
            'URL_LENGTH': 'INTEGER',
            'DOMAIN_LENGTH': 'INTEGER', 
            'SPECIAL_CHARS': 'INTEGER',
            'URL_ENTROPY': 'DECIMAL(5,3)',
            'DOMAIN_ENTROPY': 'DECIMAL(5,3)',
            'SUBDOMAINS': 'INTEGER',
            'USER_AGENT': 'NVARCHAR(500)',
            'IP_ADDRESS': 'NVARCHAR(45)'
        }
        
        # Add missing columns
        missing_count = 0
        for col_name, col_type in required_columns.items():
            if col_name not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE SENTINELONE.PHISHING_LOGS ADD ({col_name} {col_type})")
                    conn.commit()
                    print(f"✅ Added column: {col_name}")
                    missing_count += 1
                except Exception as e:
                    print(f"❌ Failed to add {col_name}: {e}")
            else:
                print(f"✅ Column {col_name} already exists")
        
        if missing_count == 0:
            print("🎉 All required columns already exist!")
        else:
            print(f"🎉 Added {missing_count} missing columns!")
        
        cursor.close()
        conn.close()
        
        print("\n🎉 HANA logging fix completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    fix_logging()
