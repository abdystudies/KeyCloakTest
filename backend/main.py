from flask import Flask, request, jsonify
from functools import wraps
import jwt
from jwt import PyJWKClient
import os

app = Flask(__name__)

# Configurazione Keycloak
KEYCLOAK_URL = "https://potential-carnival-g4wgvqqqggp5hpvwq-8080.app.github.dev/"
REALM = "master"
CLIENT_ID = "mio-client"

# URL del certificato pubblico di Keycloak
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
jwks_client = PyJWKClient(JWKS_URL)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Estrai il token dall'header Authorization
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # "Bearer <token>"
            except IndexError:
                return jsonify({'message': 'Token format invalido'}), 401
        
        if not token:
            return jsonify({'message': 'Token mancante'}), 401
        
        try:
            # Ottieni la chiave pubblica
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            
            # Verifica il token
            data = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=CLIENT_ID,
                options={"verify_exp": True}
            )
            
            # Aggiungi i dati dell'utente alla request
            request.current_user = data
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token scaduto'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'message': f'Token invalido: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

@app.route('/api/protected')
@token_required
def protected():
    user_info = request.current_user
    return jsonify({
        'message': 'Accesso consentito',
        'user': user_info.get('preferred_username'),
        'roles': user_info.get('realm_access', {}).get('roles', [])
    })

@app.route('/')
def home():
    return jsonify({
        'message': 'Flask + Keycloak Backend',
        'status': 'running'
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)