from flask import Flask, render_template, request, jsonify, send_from_directory
import requests
import os
import tempfile
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import urllib.parse

app = Flask(__name__)

# Use environment variables for sensitive info (for demonstration purposes only)
VIRUSTOTAL_API_KEY = 'a8ebea8a7f49c8a5f288734b2bd64c13d8f71549abfcb8db350ae7dc9a9026e0'
VIRUSTOTAL_API_BASE_URL = 'https://www.virustotal.com/api/v3/'

# Endpoints for scanning
VIRUSTOTAL_FILE_SCAN_URL = VIRUSTOTAL_API_BASE_URL + 'files'
VIRUSTOTAL_FILE_ANALYSIS_URL = VIRUSTOTAL_API_BASE_URL + 'analyses/{id}'
VIRUSTOTAL_URL_SCAN_URL = VIRUSTOTAL_API_BASE_URL + 'urls'
VIRUSTOTAL_URL_ANALYSIS_URL = VIRUSTOTAL_API_BASE_URL + 'urls/{id}'
VIRUSTOTAL_IP_SCAN_URL = VIRUSTOTAL_API_BASE_URL + 'ip_addresses/{ip}'

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Rate Limiting with Redis
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(file_path)
                with open(file_path, 'rb') as file_to_scan:
                    files = {'file': (filename, file_to_scan)}
                    response = requests.post(VIRUSTOTAL_FILE_SCAN_URL, headers=headers, files=files)

                if response.status_code == 200:
                    result = response.json()
                    # Fetch analysis results
                    analysis_url = result['data']['links']['self']
                    analysis_result = requests.get(analysis_url, headers=headers)
                    if analysis_result.status_code == 200:
                        return jsonify(analysis_result.json())
                    else:
                        return jsonify({'error': 'Failed to retrieve analysis'}), 400
                else:
                    return jsonify({'error': f'Failed to scan the file. Status code: {response.status_code}'}), 400
            finally:
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            return jsonify({'error': 'File type not allowed'}), 400

    elif 'url' in request.form:
        url = request.form.get('url', '').strip()
        headers = {'x-apikey': VIRUSTOTAL_API_KEY,
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded"}
        url = urllib.parse.unquote(url)
        VIRUSTOTAL_URL_SCAN_URL="https://www.virustotal.com/api/v3/urls"
        if url:
            data = {'url': url}
            response = requests.post(VIRUSTOTAL_URL_SCAN_URL, headers=headers, data=data)
            
            if response.status_code == 200:
                result = response.json()
                # Fetch URL analysis results
                analysis_url = result['data']['links']['self']
                analysis_result = requests.get(analysis_url, headers=headers)
                if analysis_result.status_code == 200:
                    return jsonify(analysis_result.json())
                else:
                    return jsonify({'error': 'Failed to retrieve URL analysis'}), 400
            else:
                return jsonify({'error': f'Failed to scan the URL. Status code: {response.status_code}'}), 400
        else:
            return jsonify({'error': 'No URL provided'}), 400

    elif 'ip' in request.form:
        ip = request.form.get('ip', '').strip()
        if ip:
            ip_info = requests.get(VIRUSTOTAL_IP_SCAN_URL.format(ip=ip), headers=headers)
            if ip_info.status_code == 200:
                return jsonify(ip_info.json())
            else:
                return jsonify({'error': f'Failed to scan IP. Status code: {ip_info.status_code}'}), 400
        else:
            return jsonify({'error': 'No IP provided'}), 400

    return jsonify({'error': 'No file, URL, or IP provided'}), 400

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                                'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=os.environ.get('FLASK_DEBUG', 'True') == 'True')