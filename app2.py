import os
import re
import urllib.parse
from datetime import datetime
import numpy as np
import joblib
import tldextract
import whois
from flask import Flask, render_template, request, jsonify
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

class PhishingDetector:
    def _init_(self, model_path='phishing_model.joblib'):
        """
        Initialize the Phishing Detector
        """
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.load_or_train_model()

    def load_or_train_model(self):
        """
        Load existing model or train a new one if not found
        """
        try:
            # Try to load existing model
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load('phishing_scaler.joblib')
                print("Existing model loaded successfully.")
                return
            
            # Generate synthetic training data if no model exists
            print("No existing model found. Generating synthetic training data...")
            X, y = self._generate_synthetic_dataset()
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            
            # Train Random Forest Classifier
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_train_scaled, y_train)
            
            # Save model and scaler
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, 'phishing_scaler.joblib')
            print("New model trained and saved successfully.")
        
        except Exception as e:
            print(f"Model training error: {e}")
            self.model = None
            self.scaler = None

    def _generate_synthetic_dataset(self, num_samples=1000):
        """
        Generate synthetic dataset for model training
        """
        # Create synthetic data
        X = np.random.rand(num_samples, 11) * 100
        y = (np.random.rand(num_samples) > 0.7).astype(int)
        
        return X, y

    def extract_features(self, url: str) -> dict:
        """
        Extract comprehensive features from a given URL
        """
        features = {}
        try:
            parsed_url = urllib.parse.urlparse(url)
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed_url.netloc)
            
            # Hostname analysis
            hostname = parsed_url.hostname or ''
            features['hostname_ip_count'] = sum(c.isdigit() for c in hostname)
            features['hostname_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\-.]', hostname))
            
            # Path and query analysis
            features['path_length'] = len(parsed_url.path)
            features['query_length'] = len(parsed_url.query)
            
            # Subdomain analysis
            extracted = tldextract.extract(url)
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            # Suspicious keyword detection
            suspicious_patterns = [
                r'login', r'verify', r'secure', r'account', 
                r'update', r'authentication', r'banking'
            ]
            features['suspicious_keywords'] = sum(
                1 for pattern in suspicious_patterns if re.search(pattern, url, re.IGNORECASE)
            )
            
            # Domain age and registration details
            try:
                domain_info = self._get_domain_info(hostname)
                features.update(domain_info)
            except Exception:
                features.update({
                    'domain_age_days': 0,
                    'registration_days_to_expiry': 0,
                    'nameserver_count': 0
                })
        
        except Exception as e:
            print(f"Feature extraction error: {e}")
            # Default features if extraction fails
            features = {
                'url_length': 0, 'domain_length': 0, 
                'hostname_ip_count': 0, 'hostname_special_chars': 0,
                'path_length': 0, 'query_length': 0,
                'subdomain_count': 0, 'suspicious_keywords': 0,
                'domain_age_days': 0, 'registration_days_to_expiry': 0,
                'nameserver_count': 0
            }
        
        return features

    def _get_domain_info(self, hostname: str) -> dict:
        """
        Retrieve domain registration information
        """
        domain_info = {}
        
        try:
            domain = whois.whois(hostname)
            
            # Domain age calculation
            if domain.creation_date:
                creation_date = domain.creation_date[0] if isinstance(domain.creation_date, list) else domain.creation_date
                domain_info['domain_age_days'] = max(0, (datetime.now() - creation_date).days)
            else:
                domain_info['domain_age_days'] = 0
            
            # Expiration days
            if domain.expiration_date:
                expiration_date = domain.expiration_date[0] if isinstance(domain.expiration_date, list) else domain.expiration_date
                domain_info['registration_days_to_expiry'] = max(0, (expiration_date - datetime.now()).days)
            else:
                domain_info['registration_days_to_expiry'] = 0
            
            # Nameserver count
            domain_info['nameserver_count'] = len(domain.name_servers) if domain.name_servers else 0
        
        except Exception:
            domain_info['domain_age_days'] = 0
            domain_info['registration_days_to_expiry'] = 0
            domain_info['nameserver_count'] = 0
        
        return domain_info

    def analyze_url(self, url: str) -> dict:
        """
        Comprehensive URL analysis
        """
        # Extract features
        features_dict = self.extract_features(url)
        
        # Predict if model is available
        if self.model and self.scaler:
            try:
                feature_vector = np.array([list(features_dict.values())])
                scaled_features = self.scaler.transform(feature_vector)
                
                # Predict phishing probability
                phishing_probability = self.model.predict_proba(scaled_features)[0][1]
                features_dict['phishing_probability'] = phishing_probability
            except Exception as e:
                print(f"Prediction error: {e}")
                features_dict['phishing_probability'] = 0.5  # Default probability
        else:
            features_dict['phishing_probability'] = 0.5
        
        # Determine threat level
        threat_level = 'Low'
        if features_dict['phishing_probability'] > 0.7:
            threat_level = 'High'
        elif features_dict['phishing_probability'] > 0.4:
            threat_level = 'Medium'
        
        features_dict['threat_level'] = threat_level
        
        # Threat indicators
        features_dict['threat_indicators'] = self._check_threat_indicators(url)
        
        return features_dict

    def _check_threat_indicators(self, url: str) -> list:
        """
        Identify specific threat indicators
        """
        indicators = []
        
        suspicious_patterns = [
            (r'https?://\d+\.\d+\.\d+\.\d+', 'IP address as hostname'),
            (r'https?://.*@', 'Credentials in URL'),
            (r'https?://.*\.exe', 'Executable file download'),
            (r'https?://.*\+', 'Encoded/obfuscated URL'),
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                indicators.append(description)
        
        return indicators

# Flask Application
app = Flask(_name_)
detector = PhishingDetector()

@app.route('/')
def index():
    """
    Render the main index page
    """
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """
    URL analysis endpoint
    """
    try:
        url = request.form.get('url', '').strip()
        
        # Validate URL
        if not url:
            return jsonify({
                'error': 'No URL provided',
                'status': 'error'
            }), 400
        
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format")
        except Exception:
            return jsonify({
                'error': 'Invalid URL format',
                'status': 'error'
            }), 400
        
        # Analyze URL
        analysis_result = detector.analyze_url(url)
        
        return jsonify({
            'status': 'success',
            'url': url,
            'phishing_probability': analysis_result.get('phishing_probability', 0.5),
            'threat_level': analysis_result.get('threat_level', 'Low'),
            'threat_indicators': analysis_result.get('threat_indicators', [])
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

if _name_ == '_main_':
    app.run(debug=True, host='0.0.0.0', port=5000)
