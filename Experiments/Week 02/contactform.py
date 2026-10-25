from flask import Flask, request, jsonify, render_template_string
import re
import uuid

app = Flask(__name__)

# Strict Email Regex Pattern
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

@app.route('/')
@app.route('/contact')
def home():
    """Serves the main application page."""
    # You can render your index.html here
    return jsonify({
        "status": "online",
        "message": "ApexContact API Server is running. Submit POST requests to /api/contact"
    })

@app.route('/api/contact', methods=['POST'])
def handle_contact_form():
    """Validates submitted contact form data server-side."""
    data = request.get_json() or {}
    
    name = str(data.get('name', '')).strip()
    email = str(data.get('email', '')).strip()
    message = str(data.get('message', '')).strip()
    
    errors = {}
    
    # 1. Server-side Name Validation
    if not name:
        errors['name'] = "Full name is required."
        
    # 2. Server-side Email Validation
    if not email:
        errors['email'] = "Email address is required."
    elif not EMAIL_REGEX.match(email):
        errors['email'] = "Please enter a valid email address (e.g., user@domain.com)."
        
    # 3. Server-side Message Validation
    if not message:
        errors['message'] = "Message field cannot be empty."
    elif len(message) < 10:
        errors['message'] = "Message must be at least 10 characters long."
        
    # If any validation failed, return 400 Bad Request with field error details
    if errors:
        return jsonify({
            "success": False,
            "message": "Validation failed on the server.",
            "errors": errors
        }), 400
        
    # Generate unique reference identifier for successful submission
    ref_id = f"MSG-{uuid.uuid4().hex[:6].upper()}"
    
    return jsonify({
        "success": True,
        "status": "200 OK (Validated Server-Side)",
        "referenceId": ref_id,
        "data": {
            "name": name,
            "email": email,
            "message": message
        }
    }), 200

if __name__ == '__main__':
    print("Starting ApexContact Python Server on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)