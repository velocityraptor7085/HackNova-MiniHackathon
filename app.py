import os
import torch
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import io
import base64
from transformers import BertTokenizer, BertForSequenceClassification
from flask import Flask, render_template, request, jsonify

# Initialize Flask app
app = Flask(__name__)

# Load the phishing detection model
model_name = "ealvaradob/bert-finetuned-phishing"
tokenizer = BertTokenizer.from_pretrained(model_name)
model = BertForSequenceClassification.from_pretrained(model_name)

def prepare_input(email_text):
    """Prepare input text for model prediction"""
    inputs = tokenizer(email_text, return_tensors="pt", padding=True, truncation=True)
    return inputs

def predict_phishing(email_text):
    """Predict phishing probability for an email"""
    inputs = prepare_input(email_text)
    with torch.no_grad():
        outputs = model(**inputs)
    
    logits = outputs.logits
    probabilities = torch.softmax(logits, dim=1)[0]
    
    phishing_prob = probabilities[1].item() * 100
    predicted_class = torch.argmax(logits, dim=1).item()
    
    return {
        'label': "Phishing" if predicted_class == 1 else "Not Phishing",
        'confidence': phishing_prob
    }

def create_confidence_plot(confidence):
    """Create a visualization of the confidence score"""
    # Close any existing plots to prevent resource leaks
    plt.close('all')
    
    # Create a new figure
    fig, ax = plt.subplots(figsize=(8, 4))
    
    # Set title and limits
    ax.set_title("Phishing Detection Confidence", fontsize=15)
    ax.set_xlim(0, 100)
    
    # Color gradient based on confidence
    color = 'green' if confidence < 50 else 'orange' if confidence < 80 else 'red'
    
    # Create horizontal bar
    ax.barh(['Phishing Probability'], [confidence], color=color)
    ax.set_xlabel("Confidence (%)", fontsize=12)
    ax.axvline(x=50, color='gray', linestyle='--', label='Threshold')
    ax.legend()
    
    # Save plot to a base64 string
    buffer = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plot_data = base64.b64encode(buffer.getvalue()).decode()
    
    # Close the plot to free up memory
    plt.close(fig)
    
    return plot_data

@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page route"""
    result = None
    plot = None
    
    if request.method == 'POST':
        email_text = request.form['email_text']
        
        try:
            # Predict phishing
            result = predict_phishing(email_text)
            
            # Create confidence plot
            plot = create_confidence_plot(result['confidence'])
        
        except Exception as e:
            result = {'label': 'Error', 'confidence': 0}
            print(f"Error occurred: {e}")
    
    return render_template('index.html', result=result, plot=plot)

@app.route('/api/detect', methods=['POST'])
def detect_phishing():
    """API endpoint for phishing detection"""
    data = request.get_json()
    email_text = data.get('email', '')
    
    result = predict_phishing(email_text)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)