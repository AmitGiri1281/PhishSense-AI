"""
PhishSense AI - Main Flask Application
Web interface for phishing message detection
"""

from flask import Flask, render_template, request, jsonify
from phishing_detector import detect_phishing, get_example_messages
import json

# Initialize Flask application
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    """
    Main route for the web application
    Handles both GET (display form) and POST (analyze message)
    """
    result = None
    example_messages = get_example_messages()
    
    if request.method == 'POST':
        # Get message from form
        message = request.form.get('message', '')
        
        # Detect phishing
        result = detect_phishing(message)
    
    # Render template with results
    return render_template(
        'index.html',
        result=result,
        examples=example_messages
    )

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    API endpoint for programmatic access
    Accepts JSON: {"message": "text to analyze"}
    Returns: JSON analysis
    """
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                'error': 'Please provide a message in JSON format',
                'example': {'message': 'Your text here'}
            }), 400
        
        message = data['message']
        result = detect_phishing(message)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'details': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring
    """
    return jsonify({
        'status': 'healthy',
        'service': 'PhishSense AI',
        'version': '1.0.0'
    })

if __name__ == '__main__':
    # Run the application
    print("=" * 50)
    print("🚀 Starting PhishSense AI Server...")
    print("📝 Local: http://127.0.0.1:5000")
    print("🌐 Network: http://your-ip:5000")
    print("=" * 50)
    
    # Start Flask server
    app.run(
        host='0.0.0.0',  # Accessible from network
        port=5000,
        debug=True,       # Auto-reload on changes
        threaded=True     # Handle multiple requests
    )