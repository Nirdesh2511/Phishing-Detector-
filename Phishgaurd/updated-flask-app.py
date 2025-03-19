from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import tldextract
import ipaddress
import ssl
import socket
import joblib
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os
from datetime import datetime



app = Flask(__name__, template_folder='Templates')
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    searches = db.relationship('SearchHistory', backref='user', lazy=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add these properties to make the User model compatible with templates
    @property
    def is_authenticated(self):
        return True
        
    @property
    def is_active(self):
        return True
        
    @property
    def is_anonymous(self):
        return False
        
    def get_id(self):
        return str(self.id)

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    searched_at = db.Column(db.DateTime, default=datetime.utcnow)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Helper functions for feature extraction
def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_at(url):
    return url.count('@')

def count_questionmark(url):
    return url.count('?')

def count_and(url):
    return url.count('&')

def count_or(url):
    return url.count('|')

def count_equal(url):
    return url.count('=')

def count_underscore(url):
    return url.count('_')

def count_tilde(url):
    return url.count('~')

def count_percent(url):
    return url.count('%')

def count_slash(url):
    return url.count('/')

def count_star(url):
    return url.count('*')

def count_colon(url):
    return url.count(':')

def count_comma(url):
    return url.count(',')

def count_semicolon(url):
    return url.count(';')

def count_dollar(url):
    return url.count('$')

def count_space(url):
    return url.count(' ')

def has_ip_address(url):
    try:
        # Check if URL contains an IP address
        pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))')
        match = pattern.search(url)
        if match:
            return 1
        return 0
    except:
        return 0

def url_length(url):
    return len(url)

def hostname_length(url):
    try:
        return len(urlparse(url).netloc)
    except:
        return 0

def suspicious_words(url):
    suspicious = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm', 'secure', 'account', 'update', 'banking', 'login']
    count = 0
    for word in suspicious:
        if word in url.lower():
            count += 1
    return count

def digit_count(url):
    return sum(c.isdigit() for c in url)

def letter_count(url):
    return sum(c.isalpha() for c in url)

def extract_features(url):
    try:
        # Extract the domain
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        
        # Feature dictionary
        features = {
            'url_length': url_length(url),
            'hostname_length': hostname_length(url),
            'count_dots': count_dots(url),
            'count_hyphens': count_hyphens(url),
            'count_at': count_at(url),
            'count_questionmark': count_questionmark(url),
            'count_and': count_and(url),
            'count_or': count_or(url),
            'count_equal': count_equal(url),
            'count_underscore': count_underscore(url),
            'count_tilde': count_tilde(url),
            'count_percent': count_percent(url),
            'count_slash': count_slash(url),
            'count_star': count_star(url),
            'count_colon': count_colon(url),
            'count_comma': count_comma(url),
            'count_semicolon': count_semicolon(url),
            'count_dollar': count_dollar(url),
            'count_space': count_space(url),
            'has_ip_address': has_ip_address(url),
            'suspicious_word_count': suspicious_words(url),
            'digit_count': digit_count(url),
            'letter_count': letter_count(url),
            'domain_length': len(domain) if domain else 0,
            'subdomain_count': 0 if not extracted.subdomain else extracted.subdomain.count('.') + 1,
            'path_length': len(parsed.path),
            'path_token_count': len([x for x in parsed.path.split('/') if x]),
            'is_https': 1 if parsed.scheme == 'https' else 0
        }
        
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default values if extraction fails
        return {feature: 0 for feature in ['url_length', 'hostname_length', 'count_dots', 'count_hyphens', 
                                         'count_at', 'count_questionmark', 'count_and', 'count_or', 
                                         'count_equal', 'count_underscore', 'count_tilde', 'count_percent', 
                                         'count_slash', 'count_star', 'count_colon', 'count_comma', 
                                         'count_semicolon', 'count_dollar', 'count_space', 'has_ip_address',
                                         'suspicious_word_count', 'digit_count', 'letter_count', 'domain_length',
                                         'subdomain_count', 'path_length', 'path_token_count', 'is_https']}

# Train the model on startup
def train_model():
    # Generate synthetic dataset for training (since we don't have real data in this example)
    # In a real application, you would load your dataset from a file
    
    # Generate 1000 legitimate URLs with features
    legitimate_features = []
    for i in range(1000):
        legitimate_features.append({
            'url_length': np.random.normal(40, 10),  # Shorter URLs for legitimate sites
            'hostname_length': np.random.normal(15, 5),
            'count_dots': np.random.normal(2, 1),
            'count_hyphens': np.random.normal(0, 1),
            'count_at': 0,  # Legitimate URLs rarely have @ symbols
            'count_questionmark': np.random.normal(0.5, 0.5),
            'count_and': np.random.normal(1, 1),
            'count_or': 0,
            'count_equal': np.random.normal(1, 1),
            'count_underscore': np.random.normal(0, 1),
            'count_tilde': 0,
            'count_percent': np.random.normal(0, 0.5),
            'count_slash': np.random.normal(3, 1),
            'count_star': 0,
            'count_colon': 1,  # Usually just the http:// part
            'count_comma': 0,
            'count_semicolon': 0,
            'count_dollar': 0,
            'count_space': 0,
            'has_ip_address': 0,
            'suspicious_word_count': np.random.normal(0, 0.5),
            'digit_count': np.random.normal(2, 2),
            'letter_count': np.random.normal(30, 10),
            'domain_length': np.random.normal(10, 3),
            'subdomain_count': np.random.normal(0.5, 0.5),
            'path_length': np.random.normal(10, 5),
            'path_token_count': np.random.normal(2, 1),
            'is_https': np.random.binomial(1, 0.7)  # 70% of legitimate sites use HTTPS
        })
    
    # Generate 1000 phishing URLs with features
    phishing_features = []
    for i in range(1000):
        phishing_features.append({
            'url_length': np.random.normal(70, 20),  # Phishing URLs tend to be longer
            'hostname_length': np.random.normal(30, 10),
            'count_dots': np.random.normal(4, 2),  # More subdomains
            'count_hyphens': np.random.normal(2, 2),
            'count_at': np.random.binomial(1, 0.1),  # @symbols sometimes appear in phishing
            'count_questionmark': np.random.normal(0.5, 0.5),
            'count_and': np.random.normal(3, 2),
            'count_or': np.random.binomial(1, 0.05),
            'count_equal': np.random.normal(2, 2),
            'count_underscore': np.random.normal(1, 1),
            'count_tilde': np.random.binomial(1, 0.05),
            'count_percent': np.random.normal(1, 1),
            'count_slash': np.random.normal(4, 2),
            'count_star': np.random.binomial(1, 0.05),
            'count_colon': np.random.normal(1, 0.5),
            'count_comma': np.random.binomial(1, 0.05),
            'count_semicolon': np.random.binomial(1, 0.05),
            'count_dollar': np.random.binomial(1, 0.05),
            'count_space': np.random.binomial(1, 0.05),
            'has_ip_address': np.random.binomial(1, 0.2),  # 20% chance of having IP address
            'suspicious_word_count': np.random.normal(2, 1),
            'digit_count': np.random.normal(8, 5),
            'letter_count': np.random.normal(50, 15),
            'domain_length': np.random.normal(15, 5),
            'subdomain_count': np.random.normal(1.5, 1),
            'path_length': np.random.normal(20, 10),
            'path_token_count': np.random.normal(4, 2),
            'is_https': np.random.binomial(1, 0.4)  # Only 40% of phishing sites use HTTPS
        })
    
    # Combine datasets
    legitimate_df = pd.DataFrame(legitimate_features)
    legitimate_df['label'] = 0  # 0 for legitimate
    
    phishing_df = pd.DataFrame(phishing_features)
    phishing_df['label'] = 1  # 1 for phishing
    
    combined_df = pd.concat([legitimate_df, phishing_df], ignore_index=True)
    
    # Split features and labels
    X = combined_df.drop('label', axis=1)
    y = combined_df['label']
    
    # Normalize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train a Random Forest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)
    
    # Save model and scaler for later use
    joblib.dump(model, 'phishing_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    
    return model, scaler

# Initialize model and scaler
model, scaler = train_model()

# User authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Function to get current user from session
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# Routes
@app.route('/')
def index():
    current_user = get_current_user()
    if current_user:
        return render_template('phishing-detector-html.html', current_user=current_user)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login-page-html.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    # Get counts for safe and phishing URLs
    safe_count = SearchHistory.query.filter_by(user_id=user_id, is_phishing=False).count()
    phishing_count = SearchHistory.query.filter_by(user_id=user_id, is_phishing=True).count()
    
    # Calculate safety score
    total_checks = safe_count + phishing_count
    safety_score = round((safe_count / total_checks) * 100) if total_checks > 0 else 100
    
    # Get recent searches
    history = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.searched_at.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                          current_user=user, 
                          safe_count=safe_count, 
                          phishing_count=phishing_count, 
                          safety_score=safety_score, 
                          history=history)

@app.route('/check', methods=['GET', 'POST'])
@login_required
def check_url():
    # Process both GET and POST requests
    if request.method == 'POST':
        url = request.form['url']
    elif request.method == 'GET':
        url = request.args.get('url')
    else:
        return jsonify({'error': 'Method not allowed'}), 405
    
    if not url:
        if request.method == 'GET':
            # If it's a GET request with no URL, redirect to main page
            return redirect(url_for('index'))
        else:
            return jsonify({'error': 'Please enter a URL'})
    
    # Extract features
    features = extract_features(url)
    
    # Convert to DataFrame with the same columns as training data
    df = pd.DataFrame([features])
    
    # Scale features
    scaled_features = scaler.transform(df)
    
    # Make prediction
    prediction = model.predict(scaled_features)[0]
    probability = model.predict_proba(scaled_features)[0][1] * 100
    
    # Save search to history
    if 'user_id' in session:
        search_history = SearchHistory(
            user_id=session['user_id'],
            url=url,
            is_phishing=bool(prediction),
            confidence=round(probability, 2)
        )
        db.session.add(search_history)
        db.session.commit()
    
    result = {
        'url': url,
        'is_phishing': bool(prediction),
        'confidence': round(probability, 2),
        'features': features
    }
    
    # For GET requests, redirect to result page or render template
    if request.method == 'GET':
        # Set flash message with result
        flash_message = f"URL: {url} is {'Phishing' if bool(prediction) else 'Safe'} with {round(probability, 2)}% confidence"
        flash(flash_message, 'danger' if bool(prediction) else 'success')
        # Redirect to the main page with the URL pre-filled
        return redirect(url_for('search', query=url))
    
    # For POST requests, return JSON
    return jsonify(result)

# Add this new route to enable the "Search Again" functionality
@app.route('/search')
@login_required
def search():
    query = request.args.get('query')
    if not query:
        return redirect(url_for('index'))
    
    current_user = get_current_user()
    # Pass the URL to the template so it can be pre-filled in the search form
    return render_template('phishing-detector-html.html', query=query, current_user=current_user)

@app.route('/history')
@login_required
def history():
    user_id = session['user_id']
    current_user = User.query.get(user_id)
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    searches = SearchHistory.query.filter_by(user_id=user_id).order_by(
        SearchHistory.searched_at.desc()
    ).paginate(page=page, per_page=per_page)
    
    return render_template('history.html', searches=searches, current_user=current_user)

@app.route('/settings')
@login_required
def settings():
    current_user = get_current_user()
    # For now, just redirect to dashboard
    # You can implement a settings page later
    return redirect(url_for('dashboard'))

# Create database tables before first request
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    if not os.path.exists('phishguard.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)