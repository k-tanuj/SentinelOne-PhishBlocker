import pandas as pd
import joblib

# Load trained model and scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

def predict_phishing(features_dict: dict):
    """
    features_dict: keys should match column names in Dataset.csv (except 'Type')
    Example:
    {
        'url_length': 54,
        'number_of_dots_in_url': 3,
        'having_repeated_digits_in_url': 0,
        'number_of_digits_in_url': 0,
        'number_of_special_char_in_url': 5,
        'number_of_hyphens_in_url': 1,
        'number_of_underline_in_url': 0,
        'number_of_slash_in_url': 3,
        'number_of_questionmark_in_url': 0,
        'number_of_equal_in_url': 0,
        'number_of_at_in_url': 0,
        'number_of_dollar_in_url': 0,
        'number_of_exclamation_in_url': 0,
        'number_of_hashtag_in_url': 0,
        'number_of_percent_in_url': 0,
        'domain_length': 19,
        'number_of_dots_in_domain': 2,
        'number_of_hyphens_in_domain': 1,
        'having_special_characters_in_domain': 0,
        'number_of_special_characters_in_domain': 0,
        'having_digits_in_domain': 0,
        'number_of_digits_in_domain': 0,
        'having_repeated_digits_in_domain': 0,
        'number_of_subdomains': 3,
        'having_dot_in_subdomain': 0,
        'having_hyphen_in_subdomain': 1,
        'average_subdomain_length': 4.333333,
        'average_number_of_dots_in_subdomain': 0.0,
        'average_number_of_hyphens_in_subdomain': 0.333333,
        'having_special_characters_in_subdomain': 0,
        'number_of_special_characters_in_subdomain': 0,
        'having_digits_in_subdomain': 0,
        'number_of_digits_in_subdomain': 0,
        'having_repeated_digits_in_subdomain': 0,
        'having_path': 1,
        'path_length': 28,
        'having_query': 0,
        'having_fragment': 0,
        'having_anchor': 0,
        'entropy_of_url': 3.807355,
        'entropy_of_domain': 3.169925
        # ... must include all 41 features from the dataset
    }
    """
    df = pd.DataFrame([features_dict])
    df_scaled = scaler.transform(df)
    pred = model.predict(df_scaled)[0]

    return "Phishing" if pred == 1 else "Legitimate"

