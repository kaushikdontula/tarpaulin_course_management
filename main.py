from flask import Flask, request, jsonify
from google.cloud import datastore
from werkzeug.utils import secure_filename
from google.cloud import storage
import os
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client(project='tarpaulin-461916')

# Update these values with your Auth0 configuration
CLIENT_ID = 'MYrIEtGPLt3bOSn89jWS2IFKd46MUuew'
CLIENT_SECRET = 'oHqSQU1tN2UkuA5Z7L00aKNuPZDDB66qmdtu4IiZLnVRzDMM6YoGa5O_OPyOW6qW'
DOMAIN = 'dev-jit6ks8bnsoewsos.us.auth0.com'

ALGORITHMS = ["RS256"]
USERS = "users"

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def verify_jwt(request):
    """Verify the JWT in the request's Authorization header"""
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        if len(auth_header) != 2 or auth_header[0] != 'Bearer':
            raise AuthError({"code": "invalid_header",
                            "description": "Authorization header must be Bearer token"}, 401)
        token = auth_header[1]
    else:
        raise AuthError({"code": "no_auth_header",
                        "description": "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description": "Invalid header. Use an RS256 signed JWT Access Token"}, 401)
    
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description": "Invalid header. Use an RS256 signed JWT Access Token"}, 401)
    
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims", "description": "incorrect claims, please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header", "description": "Unable to parse authentication token."}, 401)
        return payload
    else:
        raise AuthError({"code": "no_rsa_key", "description": "No RSA key in JWKS"}, 401)

def get_user_by_sub(sub):
    """Get user from Datastore by Auth0 sub"""
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    return results[0] if results else None

@app.route('/users/login', methods=['POST'])
def login_user():
    """
    Generate a JWT for a registered user by authenticating with Auth0.
    Returns both access_token and id_token for use in client (e.g. Postman).
    """
    if not request.is_json:
        return jsonify({"Error": "The request body is invalid"}), 400
    
    content = request.get_json()
    
    if not content or 'username' not in content or 'password' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400
    
    username = content["username"]
    password = content["password"]
    
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'openid profile email'  # 👈 Essential to get id_token
    }

    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    
    try:
        r = requests.post(url, json=body, headers=headers)
        
        if r.status_code == 200:
            auth_response = r.json()

            # Extract tokens
            access_token = auth_response.get("access_token")
            id_token = auth_response.get("id_token")

            if access_token and id_token:
                # Extract sub from id_token
                payload = jwt.get_unverified_claims(id_token)
                sub = payload.get("sub")

                return jsonify({
                    # "token": access_token,
                    "token": id_token,
                    # "sub": sub  # 👈 Helpful for Postman test scripts
                }), 200
            else:
                return jsonify({"Error": "Token(s) missing from response"}), 500

        elif r.status_code in [401, 403]:
            return jsonify({"Error": "Unauthorized"}), 401
        else:
            return jsonify({"Error": "Unauthorized"}), 401

    except requests.RequestException:
        return jsonify({"Error": "Authentication service unavailable"}), 500
    




@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        # Verify JWT and get payload
        payload = verify_jwt(request)
    except AuthError as e:
        # If token is invalid or missing, return 401
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user making the request
    user_sub = payload.get("sub")
    user_record = get_user_by_sub(user_sub)

    # If user not found or not an admin, return 403 with expected message
    if not user_record or user_record.get('role') != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Query all users
    query = client.query(kind=USERS)
    users = list(query.fetch())

    # Return only id, role, sub
    response_users = []
    for user in users:
        response_users.append({
            "id": user.key.id or user.key.name,
            "role": user.get("role"),
            "sub": user.get("sub")
        })

    return jsonify(response_users), 200




@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        # Verify JWT
        payload = verify_jwt(request)
    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401

    requester_sub = payload.get("sub")
    requester_record = get_user_by_sub(requester_sub)

    if not requester_record:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get target user by ID
    user_key = client.key(USERS, user_id)
    user = client.get(user_key)

    if not user:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Authorization check: must be admin OR the user themself
    if requester_record.get("role") != "admin" and requester_sub != user.get("sub"):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Begin constructing response
    user_data = {
        "id": user_id,
        "role": user.get("role"),
        "sub": user.get("sub")
    }

    # Optional: avatar_url if present
    if "avatar" in user and user["avatar"]:
        user_data["avatar_url"] = f"http://localhost:8080/users/{user_id}/avatar"

    # Include "courses" field for student/instructor roles
    if user.get("role") in ["student", "instructor"]:
        courses = user.get("courses", [])
        user_data["courses"] = [
            f"http://localhost:8080/courses/{course_id}" for course_id in courses
        ]

    return jsonify(user_data), 200



@app.route('/')
def index():
    return "Please navigate to the appropriate endpoints to use the Tarpaulin API"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
