![image](https://github.com/user-attachments/assets/6a754292-3275-4eb3-b84c-dbf65ff33e57)

Cyber360-Scan is a security scanner web application built with Python Flask. It allows users to:
Upload files for security scanning.
Enter URLs for analysis.
Input IP addresses or ranges for scanning.
This app integrates third-party APIs such as VirusTotal to provide detailed scan results. This application integrates some third-party APIs, like VirusTotal, for scan result details. It follows some secure design principles, including adopting a self-signed SSL certificate in order to perform security functions.

**Technical Overview**

  1.Backend framework: Python Flask  
  2.Frontend: HTML, CSS, JavaScript  
  3.API Integrations: VirusTotal API  
  
**Security**  
  1.SSL for secure communication  
  2.Hash-based lookups for file verification  
  3.File encryption for secure data handling  

**Additional Features:**  
1.Dockerized application with multi-stage builds  

**Features Overview**
**File Scanner**
**Purpose**: Allows users to upload files for security scanning  
**Capabilities**  
Accepts files up to 10MB in size. (This limit can be adjusted if required.)  
Automatically calculates file hashes for verification.  
Performs VirusTotal lookups to identify potential threats.  
Ensures user consent before uploading files to third-party services to maintain privacy.  
**URL Scanner**   
**Purpose**: Enables users to scan URLs for potential threats.  
**Capabilities**:  
Integrates with VirusTotal for thorough analysis.  
Provides results in a user-friendly format, suitable for both technical and non-technical users.  
**IP Scanner**
**Purpose:** Offers security insights for individual IPs or ranges.  
**Capabilities:**  
Scans IP addresses using integrated virustotal API.  
Displays comprehensive security insights in an easy-to-understand format.  

**Accessibility and User-friendly Experience:**  
It is designed to be simple and easy to use; the interface will be user-friendly for users of any level of technical background. The results from the scan come in neat, tabular format, which is very easy to comprehend. Besides, users will view in real time the status regarding API usage and quota limits for transparency leading to better resource management.

**Security Design Principles**   
1.Self-Signed SSL Certificate  
2.The application employs a self-signed SSL certificate to ensure secure communication between the server and clients. [ Recommended to use a valid SSL certificate]  
  
**File Handling Security**  
1.Uploaded files are stored temporarily in an encrypted format using the cryptography library's Fernet module.  
2.Files are encrypted at rest and decrypted only during scanning, minimizing risks in storage.  
3.The application validates uploaded files against a list of allowed file types to prevent malicious file uploads.  
4.File hashes are utilized to avoid unnecessary re-uploads of previously scanned files.  

**User Consent**  
1.The system is designed to allow users to choose specific services for scanning, including file uploads, URL analysis, and IP scanning.  
2.This modular approach respects user preferences and ensures that only selected data is processed.  

**Secure Inputs**  
1.All inputs, including filenames, URLs, and IP addresses, are sanitized to prevent injection attacks and ensure data integrity.  
2.URLs are decoded using the urllib.parse.unquote method to handle encoded strings securely.  
3.IP inputs are validated, and only properly formatted IP addresses are processed for scanning.  

**Rate Limiting**  
1.To prevent abuse and maintain application stability, rate limits are implemented using the Flask-Limiter library.  
2.Limits are configured as 200 requests per day and 50 requests per hour for individual users, with Redis serving as the backend storage.  

**Setup Guide**  
git clone https://github.com/kushal-190301/Cyber360-Scan.git  
cd Cyber360-Scan  

**Create and activate the virtual enviroment**
python -m venv myenv  
source myenv/bin/activate  # For Windows: myenv\Scripts\activate  

**Install Dependencies** 
pip install -r requirements.txt  

**Run the application**  
python3 app.py  

**Setup using docker**
Install the docker   
Clone this repositery   
Run the docker compose file to run the container.  

