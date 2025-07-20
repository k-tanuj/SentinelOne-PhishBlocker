#!/usr/bin/env python3
"""
Phishing Detection Demo
A working demo to check if custom URLs are predicted correctly
"""

import pandas as pd
import joblib
from url_feature_extractor import extract_features

def load_model():
    """Load the trained model and scaler"""
    try:
        model = joblib.load("model.pkl")
        scaler = joblib.load("scaler.pkl")
        return model, scaler
    except FileNotFoundError:
        print("❌ Error: Model files not found. Please run train_model.py first.")
        return None, None

def predict_url(url, model, scaler):
    """Predict if a URL is phishing or legitimate"""
    try:
        # Extract features
        features = extract_features(url)
        
        # Convert to DataFrame
        df = pd.DataFrame([features])
        
        # Scale features
        df_scaled = scaler.transform(df)
        
        # Make prediction
        prediction = model.predict(df_scaled)[0]
        confidence = model.predict_proba(df_scaled)[0]
        
        result = "🚨 PHISHING" if prediction == 1 else "✅ LEGITIMATE"
        confidence_score = confidence[1] if prediction == 1 else confidence[0]
        
        return result, confidence_score, features
        
    except Exception as e:
        return f"❌ Error: {str(e)}", 0.0, {}

def print_analysis(url, result, confidence, features):
    """Print detailed analysis of the URL"""
    print(f"\n{'='*60}")
    print(f"🔍 URL ANALYSIS: {url}")
    print(f"{'='*60}")
    print(f"PREDICTION: {result}")
    print(f"CONFIDENCE: {confidence:.2%}")
    print(f"\n📊 KEY FEATURES:")
    print(f"  • URL Length: {features.get('url_length', 0)} characters")
    print(f"  • Domain Length: {features.get('domain_length', 0)} characters")
    print(f"  • Special Characters: {features.get('number_of_special_char_in_url', 0)}")
    print(f"  • Dots in URL: {features.get('number_of_dots_in_url', 0)}")
    print(f"  • Subdomains: {features.get('number_of_subdomains', 0)}")
    print(f"  • Has Path: {'Yes' if features.get('having_path', 0) == 1 else 'No'}")
    print(f"  • Has Query: {'Yes' if features.get('having_query', 0) == 1 else 'No'}")
    print(f"  • URL Entropy: {features.get('entropy_of_url', 0):.2f}")
    print(f"  • Domain Entropy: {features.get('entropy_of_domain', 0):.2f}")

def demo_mode():
    """Interactive demo mode"""
    print("\n🛡️  PHISHING DETECTION DEMO")
    print("=" * 50)
    
    # Load model
    model, scaler = load_model()
    if model is None:
        return
    
    print("✅ Model loaded successfully!")
    print("📝 Enter URLs to check (type 'quit' to exit)")
    print("=" * 50)
    
    while True:
        url = input("\n🔗 Enter URL: ").strip()
        
        if url.lower() in ['quit', 'exit', 'q']:
            print("👋 Goodbye!")
            break
            
        if not url:
            continue
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        result, confidence, features = predict_url(url, model, scaler)
        print_analysis(url, result, confidence, features)

def test_sample_urls():
    """Test with sample URLs"""
    print("\n🧪 TESTING SAMPLE URLs")
    print("=" * 50)
    
    # Load model
    model, scaler = load_model()
    if model is None:
        return
    
    # Sample URLs to test
    test_urls = [
        "https://www.google.com",
        "https://github.com/microsoft/vscode",
        "https://www.paypal.com/signin",
        "http://phishing-site-123.com/login.php?redirect=bank.com",
        "https://suspicious-banking-site.net/secure-login/?user=admin",
        "https://bit.ly/fake-bank-login",
        "https://192.168.1.1/admin/login",
        "https://www.amazon.com/products/electronics"
    ]
    
    for url in test_urls:
        result, confidence, features = predict_url(url, model, scaler)
        print_analysis(url, result, confidence, features)
        print("\n" + "-"*60)

def main():
    """Main function"""
    print("🛡️  PHISHING DETECTION SYSTEM")
    print("=" * 50)
    print("Choose an option:")
    print("1. Interactive Demo (Enter custom URLs)")
    print("2. Test Sample URLs")
    print("3. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            demo_mode()
        elif choice == '2':
            test_sample_urls()
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
