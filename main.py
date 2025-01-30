from flask import Flask, request, render_template, flash, redirect, url_for
import os
import subprocess
import requests
import socket

app = Flask(_name_)
app.secret_key = "your_secret_key"  # Required for flash messages

# Ensure the reports directory exists
if not os.path.exists("reports"):
    os.makedirs("reports")

def detect_framework(url):
    """
    Detects the framework used by the target web application.
    :param url: Target website URL
    :return: Framework name or "Unknown Framework"
    """
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Check for "X-Powered-By" in response headers
        if 'X-Powered-By' in headers:
            return headers['X-Powered-By']

        # Check for popular frameworks in HTML content
        elif 'wordpress' in response.text.lower():
            return "WordPress"
        elif 'django' in response.text.lower():
            return "Django"
        elif 'laravel' in response.text.lower():
            return "Laravel"
        else:
            return "Unknown Framework"
    except Exception as e:
        return f"Error detecting framework: {str(e)}"

def get_ip_address(url):
    """
    Resolves the IP address of the target domain.
    :param url: Target website URL
    :return: IP address of the domain
    """
    try:
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error resolving IP: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    # Sanitize URL for filenames and extract domain
    sanitized_url = url.replace('http://', '').replace('https://', '').replace('/', '_')
    target_domain = url.replace('http://', '').replace('https://', '').split('/')[0]  # Extract domain

    report_path = f"reports/{sanitized_url}_report.txt"

    try:
        # Detect the IP address
        ip_address = get_ip_address(url)

        # Run Nmap scan
        nmap_result = subprocess.getoutput(f"nmap -A {target_domain}")

        # Run SQLMap scan
        sqlmap_result = subprocess.getoutput(f"sqlmap -u {url} --batch --level=2 --risk=2")

        # Detect the framework
        framework = detect_framework(url)

        # Combine results and save to a report
        with open(report_path, 'w') as report:
            report.write("=== Target Information ===\n")
            report.write(f"IP Address: {ip_address}\n")
            report.write("\n\n=== NMAP SCAN RESULTS ===\n")
            report.write(nmap_result)
            report.write("\n\n=== SQLMAP SCAN RESULTS ===\n")
            report.write(sqlmap_result)
            report.write("\n\n=== FRAMEWORK DETECTION ===\n")
            report.write(f"Detected Framework: {framework}\n")

        flash("Scan complete! Report is ready.", "success")
        return render_template('result.html', framework=framework, nmap=nmap_result, sqlmap=sqlmap_result, ip_address=ip_address)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('home'))

if _name_ == "_main_":
    app.run(debug=True, host='0.0.0.0')



