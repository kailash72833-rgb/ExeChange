from flask import Flask, request, jsonify
import requests
import os
import hashlib
from datetime import datetime, timezone, timedelta
import time
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)
SESSION = requests.Session()
SESSION.verify = False
requests.packages.urllib3.disable_warnings()

# ====================== CONFIG ======================
BASE_URL = "https://100067.connect.garena.com"
APP_ID = "100067"

# ====================== HELPERS ======================
def sha256_upper(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest().upper()

def log_info(msg): print(f"[INFO] {msg}")
def log_error(msg): print(f"[ERROR] {msg}")

def eat_to_access_token(eat_token: str):
    """Convert EAT to access token (optional, but kept for convenience)"""
    try:
        callback_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        resp = SESSION.get(callback_url, allow_redirects=True, timeout=30)
        if 'help.garena.com' in resp.url:
            parsed = urlparse(resp.url)
            params = parse_qs(parsed.query)
            if 'access_token' in params:
                return {
                    "success": True,
                    "access_token": params['access_token'][0],
                    "region": params.get('region', [''])[0],
                    "game_uid": params.get('account_id', [''])[0],
                    "nickname": params.get('nickname', [''])[0]
                }
        return {"success": False, "error": "INVALID_EAT_TOKEN"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ====================== GARENA BINDING CLASS ======================
class GarenaBind:
    def __init__(self, access_token):
        self.access_token = access_token
        self.base_url = BASE_URL
        self.app_id = APP_ID
        self.session = SESSION

    def _request(self, method, endpoint, data=None, params=None, headers=None):
        url = f"{self.base_url}{endpoint}"
        default_headers = {
            'User-Agent': 'GarenaMSDK/4.0.19P9(Redmi Note 5;Android 9;en;US;)',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        if headers:
            default_headers.update(headers)
        try:
            if method.upper() == 'GET':
                r = self.session.get(url, params=params, headers=default_headers, timeout=15)
            else:
                r = self.session.post(url, data=data, headers=default_headers, timeout=15)
            return r.status_code, r.json() if r.text else {}
        except Exception as e:
            return 500, {"error": str(e)}

    def send_otp(self, email):
        endpoint = "/game/account_security/bind:send_otp"
        data = {
            'app_id': self.app_id,
            'access_token': self.access_token,
            'email': email,
            'locale': 'en_MA'
        }
        # The Cookie may be optional; keep it if needed
        headers = {
            'Cookie': 'datadome=q2ZtAABCjPFEIWeaxYM2YvfxEUPXT_GLUp4gpUOEUPlI9jGXkQLS5uoG_HBUBnJvC0s0CBfHF6h4FUg7mBumLRO1jpLh4um4CbF4ykEKTLv5f27DgR_nkEJcZm_Sj1E~'
        }
        code, resp = self._request('POST', endpoint, data=data, headers=headers)
        return resp if code == 200 else {"error": "HTTP " + str(code)}

    def verify_otp(self, otp, email):
        endpoint = "/game/account_security/bind:verify_otp"
        data = {
            'app_id': self.app_id,
            'access_token': self.access_token,
            'otp': otp,
            'email': email
        }
        code, resp = self._request('POST', endpoint, data=data)
        return resp if code == 200 else {"error": "HTTP " + str(code)}

    def verify_identity(self, security_code):
        endpoint = "/game/account_security/bind:verify_identity"
        hashed = sha256_upper(security_code)
        data = {
            'app_id': self.app_id,
            'access_token': self.access_token,
            'secondary_password': hashed
        }
        headers = {
            'User-Agent': 'GarenaMSDK/4.0.19P10(ASUS_Z01QD;Android 9;en;US;)',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'com.garena.game.kgid'
        }
        code, resp = self._request('POST', endpoint, data=data, headers=headers)
        return resp if code == 200 else {"error": "HTTP " + str(code)}

    def verify_identity_with_otp(self, email, otp):
        endpoint = "/game/account_security/bind:verify_identity_with_otp"
        data = {
            'app_id': self.app_id,
            'access_token': self.access_token,
            'email': email,
            'otp': otp
        }
        code, resp = self._request('POST', endpoint, data=data)
        return resp if code == 200 else {"error": "HTTP " + str(code)}

    def create_rebind_request(self, identity_token, verifier_token, new_email):
        endpoint = "/game/account_security/bind:create_rebind_request"
        data = {
            'app_id': self.app_id,
            'access_token': self.access_token,
            'identity_token': identity_token,
            'verifier_token': verifier_token,
            'email': new_email
        }
        code, resp = self._request('POST', endpoint, data=data)
        return resp if code == 200 else {"error": "HTTP " + str(code)}

    def cancel_request(self):
        endpoint = "/game/account_security/bind:cancel_request"
        data = {'app_id': self.app_id, 'access_token': self.access_token}
        code, resp = self._request('POST', endpoint, data=data)
        return resp if code == 200 else {"error": "HTTP " + str(code)}

# ====================== TOKEN EXTRACTION ======================
def get_access_token_from_args(args):
    eat = args.get('eat')
    access = args.get('access')
    if not eat and not access:
        return None, "Either 'eat' or 'access' parameter is required"
    if eat and access:
        return None, "Provide either 'eat' or 'access', not both"
    if eat:
        conv = eat_to_access_token(eat)
        if not conv.get('success'):
            return None, conv.get('error', 'EAT conversion failed')
        return conv['access_token'], None
    return access, None

# ====================== FLASK ENDPOINTS ======================
@app.route('/')
def index():
    return jsonify({
        "success": True,
        "message": "Garena Change Email API",
        "endpoints": {
            "/sendotp": "Send OTP to email (need eat or access + email)",
            "/changeemail": "Change recovery email (see parameters below)",
            "/cancelrequest": "Cancel any pending email change request"
        },
        "change_email_params": {
            "required": "new_email, new_otp",
            "identity_verification": "Either (security_code) OR (current_email + otp)",
            "example_with_security": "/changeemail?access=xxx&new_email=new@example.com&new_otp=123456&security_code=your_secondary_password",
            "example_with_current_otp": "/changeemail?access=xxx&new_email=new@example.com&new_otp=123456&current_email=old@example.com&otp=654321"
        },
        "credits": "@DANGER_FF_LIKE"
    })

@app.route('/sendotp', methods=['GET'])
def send_otp():
    token, err = get_access_token_from_args(request.args)
    if err:
        return jsonify({"success": False, "error": err}), 400
    email = request.args.get('email')
    if not email:
        return jsonify({"success": False, "error": "email parameter required"}), 400
    api = GarenaBind(token)
    resp = api.send_otp(email)
    if resp.get('result') == 0:
        return jsonify({"success": True, "message": "OTP sent", "data": resp})
    return jsonify({"success": False, "error": resp.get('message', 'Failed'), "details": resp}), 400

@app.route('/changeemail', methods=['GET'])
def change_email():
    token, err = get_access_token_from_args(request.args)
    if err:
        return jsonify({"success": False, "error": err}), 400
    new_email = request.args.get('new_email')
    new_otp = request.args.get('new_otp')
    if not new_email or not new_otp:
        return jsonify({"success": False, "error": "new_email and new_otp required"}), 400

    # Identity verification: either security_code OR (current_email + otp)
    sec = request.args.get('security_code')
    cur_email = request.args.get('current_email')
    cur_otp = request.args.get('otp')
    if not sec and not (cur_email and cur_otp):
        return jsonify({"success": False, "error": "Either security_code or (current_email+otp) required"}), 400
    if sec and (cur_email or cur_otp):
        return jsonify({"success": False, "error": "Provide only one verification method"}), 400

    api = GarenaBind(token)

    # Step 1: Verify identity
    if sec:
        verify = api.verify_identity(sec)
    else:
        verify = api.verify_identity_with_otp(cur_email, cur_otp)

    if verify.get('result') != 0:
        return jsonify({"success": False, "error": "Identity verification failed", "details": verify}), 400
    identity_token = verify.get('identity_token')
    if not identity_token:
        return jsonify({"success": False, "error": "No identity token", "details": verify}), 500

    # Step 2: Verify OTP on new email
    otp_verify = api.verify_otp(new_otp, new_email)
    if otp_verify.get('result') != 0:
        return jsonify({"success": False, "error": "New email OTP verification failed", "details": otp_verify}), 400
    verifier = otp_verify.get('verifier_token')

    # Step 3: Create rebind request
    rebind = api.create_rebind_request(identity_token, verifier, new_email)
    if rebind.get('result') == 0:
        return jsonify({"success": True, "message": "Change email request created", "data": rebind})
    return jsonify({"success": False, "error": "Change failed", "details": rebind}), 400

@app.route('/cancelrequest', methods=['GET'])
def cancel_request():
    token, err = get_access_token_from_args(request.args)
    if err:
        return jsonify({"success": False, "error": err}), 400
    api = GarenaBind(token)
    resp = api.cancel_request()
    if resp.get('result') == 0:
        return jsonify({"success": True, "message": "Request cancelled", "data": resp})
    return jsonify({"success": False, "error": "Cancel failed", "details": resp}), 400

# ====================== ERROR HANDLERS ======================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "NOT_FOUND"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "SERVER_ERROR"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8001))
    log_info(f'Starting Change Email API on port {port}')
    app.run(host='0.0.0.0', port=port, debug=True)