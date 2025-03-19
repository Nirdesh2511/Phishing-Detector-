# Phishing-Detector-
# 🔒 PhishGuard - Phishing URL Detection System

## 🚀 Overview
PhishGuard is a **Flask-based web application** that detects phishing URLs using **machine learning**. It extracts key URL features, predicts phishing probabilities, and provides a user-friendly interface to check URLs in real-time.

## 🏗 Features
- ✅ **Machine Learning Model**: Uses a **Random Forest Classifier** trained on phishing and legitimate URLs.  
- ✅ **Feature Extraction**: Analyzes URLs based on structure, domain properties, and suspicious patterns.  
- ✅ **User Authentication**: Secure login & registration system with hashed passwords.  
- ✅ **Search History**: Stores URL checks in a database for future reference.  
- ✅ **Real-time Detection**: Predicts whether a URL is phishing with a confidence score.  
- ✅ **Flask API**: Supports both web-based and API-based URL checks.  


## 🛠 Installation & Setup

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard
2️⃣ Install Dependencies
Ensure you have Python 3.10+ installed, then run:

pip install -r requirements.txt

3️⃣ Set Up Database

flask db upgrade

4️⃣ Run the Application

python updated-flask-app.py

Access the web app at http://127.0.0.1:5000/.


🎯 How It Works
User logs in and enters a URL to check.
The app extracts features from the URL (length, domain properties, special characters, etc.).
The pre-trained machine learning model predicts if the URL is phishing.
Results are displayed with a confidence score.
Users can view past searches in the history section.

🧩 Technologies Used
Python (Flask)
Scikit-Learn (Random Forest Classifier)
Pandas & NumPy (Feature extraction)
SQLite (User & search history database)
Joblib (Model serialization)
