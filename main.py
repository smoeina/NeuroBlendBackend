from flask import Flask, request, jsonify, url_for, render_template, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
import jwt
import datetime
import io
import base64
from PIL import Image
from glob import glob
import sys

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "smoein2010@gmail.com"
app.config['MAIL_PASSWORD'] = 'oewgyrkeoaazykkm'

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
models = []
models_info = []

def find_available_models():
    global models_info
    model_dirs = glob('models/**/*.h5', recursive=True)
    for model_dir in model_dirs:
        data_type = model_dir.split('/')[1]
        task_name = model_dir.split('/')[2]
        model_name = model_dir.split('/')[3]
        models_info.append([data_type, task_name, model_name])
        print('importing model class ...')
        sys.path.append('/'.join(model_dir.split('/')[0:-1]))

    return models_info, model_dirs


def load_models():
    global models
    _, model_dirs = find_available_models()
    for model_dir in model_dirs:
        classname_of_model = model_dir.split('/')[-2].upper()
        classname_of_model = __import__(classname_of_model)
        model_class_contructor = getattr(classname_of_model, "EDSR_X4")
        model = model_class_contructor(model_dir)
        models.append(model)

    return models
# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Float, default=0)


def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECRET_KEY'])


def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECRET_KEY'], max_age=expiration)
    except Exception as e:
        return None
    return email


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    password = data['password']

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered.'}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    token = generate_verification_token(email)
    verification_link = url_for('confirm_email', token=token, _external=True)
    send_verification_email(email, verification_link)

    return jsonify({'message': 'User registered successfully! Please check your email to verify your account.'})


def send_verification_email(email, verification_link):
    msg = Message('Confirm Your Email', sender="smoein2010@gmail.com", recipients=[email])
    html = render_template('email_verification.html', verification_link=verification_link)
    msg.html = html
    mail.send(msg)


@app.route('/confirm_email/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        return 'The confirmation link is invalid or has expired.', 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.verified = True
        db.session.commit()
        return redirect('http://localhost:8100/email-verified')
    return 'User not found', 404


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    if not user.verified:
        return jsonify({'message': 'Account not verified. Please check your email.'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': 'Logged in successfully', 'token': token}), 200


def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/process_image', methods=['POST'])
# @token_required
def process_image():
    data = request.get_json()
    print(data)
    if 'image' not in data:
        return jsonify({'message': 'No image data provided'}), 400

    image_data = data['image']
    try:
        # Decode the base64 image
        image_data = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_data))
        print(image)
        # Perform a simple operation on the image, e.g., convert to grayscale
        image = image.convert('L')

        img_io = io.BytesIO()
        image.save("img_io.jpeg", 'JPEG')
        img_io.seek(0)

        return send_file(img_io, mimetype='image/jpeg', as_attachment=True, download_name='processed_image.jpg')
    except Exception as e:
        return jsonify({'message': 'Error processing image', 'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    CORS(app)
