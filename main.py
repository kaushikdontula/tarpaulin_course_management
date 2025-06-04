from flask import Flask, request, jsonify, Response
from google.cloud import datastore
from werkzeug.utils import secure_filename
from google.cloud import storage
import os
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from datetime import timedelta
from flask import send_file
from io import BytesIO
from urllib.parse import urljoin


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

    base_url = request.host_url

    # Optional: avatar_url if present
    if "avatar" in user and user["avatar"]:
        user_data["avatar_url"] = urljoin(base_url, f"users/{user_id}/avatar")

    # Include "courses" field for student/instructor roles
    if user.get("role") in ["student", "instructor"]:
        courses = user.get("courses", [])
        user_data["courses"] = [
            urljoin(base_url, f"courses/{course_id}") for course_id in courses
        ]

    return jsonify(user_data), 200



@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def upload_user_avatar(user_id):
    # Step 1: Verify JWT first
    try:
        payload = verify_jwt(request)
    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401

    sub = payload.get("sub")

    # Step 2: Permission check
    user_key = client.key(USERS, user_id)
    user = client.get(user_key)
    if not user or user.get("sub") != sub:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Step 3: Check for 'file' key after JWT & permission validated
    if 'file' not in request.files:
        return jsonify({"Error": "The request body is invalid"}), 400

    file = request.files['file']
    if not file.filename.endswith('.png'):
        return jsonify({"Error": "Only .png files are accepted"}), 400

    # Upload file to GCS
    storage_client = storage.Client(project='tarpaulin-461916')
    bucket = storage_client.bucket("tarpaulin-avatars1234")
    filename = secure_filename(f"user_{user_id}.png")
    blob = bucket.blob(filename)
    blob.upload_from_file(file, content_type='image/png')

    # Update user avatar in datastore
    user['avatar'] = filename
    client.put(user)

    avatar_url = f"{request.host_url.rstrip('/')}/users/{user_id}/avatar"
    return jsonify({"avatar_url": avatar_url}), 200








@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_user_avatar(user_id):
    # Step 1: Verify JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify({"Error": "Unauthorized"}), 401

    sub = payload.get("sub")
    
    # Step 2: Fetch the user from Datastore
    user_key = client.key(USERS, user_id)
    user = client.get(user_key)
    
    if not user:
        return jsonify({"Error": "User not found"}), 403

    # Step 3: Verify that JWT belongs to this user
    if user.get("sub") != sub:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Step 4: Check if avatar exists
    if 'avatar' not in user or not user['avatar']:
        return jsonify({"Error": "Not found"}), 404

    # Step 5: Download the avatar file from GCS
    storage_client = storage.Client(project='tarpaulin-461916')
    bucket = storage_client.bucket("tarpaulin-avatars1234")
    blob = bucket.blob(user['avatar'])

    if not blob.exists():
        return jsonify({"Error": "Avatar file not found in storage"}), 404

    avatar_data = blob.download_as_bytes()

    # Step 6: Send the file as a response
    return send_file(
        BytesIO(avatar_data),
        mimetype='image/png',
        as_attachment=False,
        download_name='avatar.png'  # File name doesn't matter per spec
    )


@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_user_avatar(user_id):
    # Step 1: Verify JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify({"Error": "Unauthorized"}), 401

    sub = payload.get("sub")

    # Step 2: Fetch user from Datastore
    user_key = client.key(USERS, user_id)
    user = client.get(user_key)

    if not user:
        # User not found, but no explicit status mentioned in spec here.
        # Return 403 as user does not belong to this JWT or not found
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Step 3: Verify JWT belongs to user_id
    if user.get("sub") != sub:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Step 4: Check if user has avatar
    if 'avatar' not in user or not user['avatar']:
        return jsonify({"Error": "Not found"}), 404

    # Step 5: Delete the avatar file from GCS
    storage_client = storage.Client(project='tarpaulin-461916')
    bucket = storage_client.bucket("tarpaulin-avatars1234")
    blob = bucket.blob(user['avatar'])

    if not blob.exists():
        # If blob file does not exist in GCS, still treat as 404 (avatar not found)
        return jsonify({"Error": "Not found"}), 404

    blob.delete()

    # Step 6: Remove avatar reference from user in Datastore
    user['avatar'] = None
    client.put(user)

    # Step 7: Return 204 No Content on success
    return Response(status=204)



COURSES = "courses"

@app.route('/courses', methods=['POST'])
def create_course():
    # Step 1: Verify JWT
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify({"Error": "Unauthorized"}), 401

    # Step 2: Verify user role is admin
    user_sub = payload.get("sub")
    user_record = get_user_by_sub(user_sub)
    if not user_record or user_record.get("role") != "admin":
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Step 3: Validate JSON body
    if not request.is_json:
        return jsonify({"Error": "The request body is invalid"}), 400

    data = request.get_json()

    # Required fields and basic validations
    required_fields = ["subject", "number", "title", "term", "instructor_id"]
    for field in required_fields:
        if field not in data:
            return jsonify({"Error": f"The request body is invalid"}), 400

    subject = data["subject"]
    number = data["number"]
    title = data["title"]
    term = data["term"]
    instructor_id = data["instructor_id"]

    # Validate field types and constraints
    if not isinstance(subject, str) or len(subject) > 4 or len(subject) == 0:
        return jsonify({"Error": "Invalid subject"}), 400
    if not isinstance(number, int):
        return jsonify({"Error": "Invalid number"}), 400
    if not isinstance(title, str) or len(title) > 50 or len(title) == 0:
        return jsonify({"Error": "Invalid title"}), 400
    if not isinstance(term, str) or len(term) > 10 or len(term) == 0:
        return jsonify({"Error": "Invalid term"}), 400
    if not isinstance(instructor_id, int):
        return jsonify({"Error": "Invalid instructor_id"}), 400

    # Step 4: Verify instructor exists and is a user in Datastore
    instructor_key = client.key(USERS, instructor_id)
    instructor = client.get(instructor_key)
    if not instructor:
        return jsonify({"Error": "Instructor does not exist"}), 400

    # Optional: Could also verify instructor's role == 'instructor' if needed

    # Step 5: Create new course entity
    course_key = client.key(COURSES)
    course = datastore.Entity(key=course_key)
    course.update({
        "subject": subject,
        "number": number,
        "title": title,
        "term": term,
        "instructor_id": instructor_id
    })

    client.put(course)

    base_url = request.host_url.rstrip('/')
    self_url = f"{base_url}/courses/{course.key.id}"


    # Step 6: Return 201 Created with course details including its ID
    response_course = {
        "id": course.key.id,
        "subject": subject,
        "number": number,
        "title": title,
        "term": term,
        "instructor_id": instructor_id,
        "self": self_url
    }

    return jsonify(response_course), 201




@app.route('/')
def index():
    return "Please navigate to the appropriate endpoints to use the Tarpaulin API"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
