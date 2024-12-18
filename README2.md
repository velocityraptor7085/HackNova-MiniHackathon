# 🔍 PhishingDetector: AI-Driven URL Analysis Tool 🌐  

PhishingDetector is an advanced AI-powered tool for detecting phishing URLs. With a robust backend and an intuitive web interface, this project empowers users to assess the risk of suspicious URLs by leveraging machine learning and comprehensive feature extraction.

---
![WhatsApp Image 2024-12-18 at 13 22 37_ba7e75e8](https://github.com/user-attachments/assets/eee52d0b-81a1-4a47-bae6-f65f74c67dca)
---

## 🚀 Features  

- **AI-Driven Analysis**: Predicts phishing probability using a trained Random Forest model.  
- **Feature Extraction**: Extracts key indicators such as URL length, domain age, subdomains, and suspicious patterns.  
- **Threat Level Detection**: Classifies URLs as Low, Medium, or High threat based on phishing probability.  
- **Comprehensive Indicators**: Highlights specific threat indicators like IP address hostnames or executable file links.  
- **Interactive Interface**: Web-based UI for analyzing URLs in real-time.  

---

## 🤖 How It Works  

1. **Feature Extraction**: The backend extracts over 10 URL features, including domain metadata and suspicious keywords.  
2. **Machine Learning Model**: A Random Forest Classifier predicts phishing probability based on the extracted features.  
3. **Threat Assessment**: Results include the phishing probability, threat level, and specific threat indicators.  

---

## 🛠️ Installation and Setup  

### Prerequisites  
- Python 3.8+  
- Flask  
- Required libraries (`joblib`, `numpy`, `sklearn`, `tldextract`, `whois`)  

### Steps  

1. Clone the repository:  
   ```bash
   git clone https://github.com/YourUsername/PhishingDetector.git
   cd PhishingDetector
   ```

2. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:  
   ```bash
   python app.py
   ```

4. Access the app at `http://localhost:5000` in your browser.  

---

## 🔒 Why This Project Matters  

Phishing remains one of the most prevalent cybersecurity threats, exploiting human vulnerabilities to compromise sensitive information.  
This project demonstrates the potential of **AI-driven solutions** in combating phishing by:  

- Automating threat detection and response.  
- Supporting real-time analysis with user-friendly tools.  

**PhishingDetector bridges the gap between technical sophistication and accessibility, empowering users to stay secure online.**

---

## 📜 License  

This project is licensed under the [MIT License](LICENSE).  

---

🌐 **PhishingDetector**: Making the internet a safer place, one URL at a time.
```
