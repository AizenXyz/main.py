from flask import Flask, jsonify, request, make_response
from ua_parser import user_agent_parser
import requests
import hashlib
from datetime import datetime

app = Flask(__name__)

SUPABASE_URL = "https://tvzzbuoyuqhttydpdqbo.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR2enpidW95dXFodHR5ZHBkcWJvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDU4NTMwNTMsImV4cCI6MjA2MTQyOTA1M30._l805NDjwynqJEMCoTssCIc_fW2z50gNpMGYckZpAhE"
SUPABASE_HEADERS = {
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "apikey": SUPABASE_KEY
}

def generate_unique_cookie_id(ip, user_agent):
    combined = f"{ip}_{user_agent}_{datetime.utcnow().isoformat()}"
    return hashlib.sha256(combined.encode()).hexdigest()

def store_cookie_in_supabase(cookie_id, ip, user_agent):
    data = {
        "cookie_id": cookie_id,
        "ip": ip,
        "user_agent": user_agent,
        "created_at": datetime.utcnow().isoformat()
    }
    try:
        response = requests.post(f"{SUPABASE_URL}/rest/v1/cookies", json=data, headers=SUPABASE_HEADERS)
        response.raise_for_status()
    except requests.RequestException as e:
        app.logger.error(f"Erro ao armazenar cookie no Supabase: {e}")

def cookie_exists_in_supabase(cookie_id):
    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/cookies?cookie_id=eq.{cookie_id}",
            headers=SUPABASE_HEADERS
        )
        return len(response.json()) > 0
    except requests.RequestException:
        return False

def check_security_headers():
    headers = request.headers
    issues = []
    if 'X-Frame-Options' not in headers:
        issues.append("Falta X-Frame-Options: vulneravel a clickjacking")
    if 'X-Content-Type-Options' not in headers:
        issues.append("Falta X-Content-Type-Options: vulneravel a MIME sniffing")
    if 'Content-Security-Policy' not in headers:
        issues.append("Falta Content-Security-Policy: vulneravel a XSS")
    if 'Strict-Transport-Security' not in headers:
        issues.append("Falta Strict-Transport-Security: conexao menos segura")
    return issues

def analyze_user_agent(user_agent):
    parsed_ua = user_agent_parser.Parse(user_agent)
    issues = []
    if 'bot' in user_agent.lower():
        issues.append("User-agent indica um bot")
    if not parsed_ua['user_agent']['family']:
        issues.append("Navegador desconhecido: possivel spoofing")
    if parsed_ua['os']['family'] == 'unknown':
        issues.append("Sistema operacional desconhecido: possivel spoofing")
    return issues

@app.route('/')
def get_info():
    client_ip = request.remote_addr

    try:
        ipinfo_response = requests.get(f"https://ipinfo.io/{client_ip}/json")
        ipinfo_data = ipinfo_response.json()
    except:
        ipinfo_data = {"error": "ipinfo_unavailable"}

    user_agent = request.headers.get('User-Agent', 'desconhecido')
    parsed_ua = user_agent_parser.Parse(user_agent)

    cookie_id = request.cookies.get('cookie_id')
    if not cookie_id or not cookie_exists_in_supabase(cookie_id):
        cookie_id = generate_unique_cookie_id(client_ip, user_agent)
        store_cookie_in_supabase(cookie_id, client_ip, user_agent)

    security_issues = []
    security_issues.extend(check_security_headers())
    security_issues.extend(analyze_user_agent(user_agent))

    if security_issues:
        app.logger.warning(f"Problemas de seguranca detectados para IP {client_ip}: {security_issues}")

    combined_info = {
        "ip": ipinfo_data.get("ip", "desconhecido"),
        "navegador": parsed_ua['user_agent']['family'],
        "cookie_id": cookie_id
    }

    response = make_response(jsonify(combined_info))
    response.set_cookie('cookie_id', cookie_id, max_age=31536000)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)