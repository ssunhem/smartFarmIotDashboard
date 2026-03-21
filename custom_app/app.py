import os
import json
import eventlet
import logging
import sys
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS 
from flask_mqtt import Mqtt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
from flask_apscheduler import APScheduler

eventlet.monkey_patch()

# --- Configuration ---
# Database (SQLite file inside the Docker container)
db_uri = 'postgresql://smartfarm_user:a_very_secure_db_password@postgres_db:5432/sensor_metrics_db'

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_secret_key_for_dev')

db = SQLAlchemy(app)
CORS(app) # Initialize CORS with the Flask app
# app.config['MQTT_CLIENT_ID'] = 'gunicorn-worker-' + os.urandom(8).hex()
topic_base = "farm" # Base topic for control and telemetry

scheduler = APScheduler()

# --- START: LOGGING CONFIGURATION ---
def configure_logging(app):
    # 1. Set Flask and Python root logger to DEBUG level
    app.logger.setLevel(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    
    # 2. Create a handler to pipe logs to stdout (Docker's standard output)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    handler.setFormatter(formatter)
    
    # Add the handler to Flask's logger if it's not already there
    if not app.logger.handlers:
        app.logger.addHandler(handler)

    # 3. Suppress some excessively verbose libraries if needed (optional)
    logging.getLogger('eventlet.wsgi.server').setLevel(logging.INFO)
    logging.getLogger('werkzeug').setLevel(logging.INFO)

configure_logging(app)
    
# --- END: LOGGING CONFIGURATION ---

# --- SocketIO Initialization ---
# Setting cors_allowed_origins="*" is vital for frontend connection
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True)

app.config['MQTT_BROKER_URL'] = 'mosquitto'
app.config['MQTT_BROKER_PORT'] = 1883
app.config['MQTT_USERNAME'] = ''  # set the username here if you need authentication for the broker
app.config['MQTT_PASSWORD'] = ''  # set the password here if the broker demands authentication
app.config['MQTT_KEEPALIVE'] = 5  # set the time interval for sending a ping to the broker to 5 seconds
app.config['MQTT_TLS_ENABLED'] = False  # set TLS to disabled for testing purposes
mqtt = Mqtt(app)
mqtt.subscribe('farm/#')
weekdays = ["mon","tue","wed","thu","fri","sat","sun"]

# ... (Existing app, db, and cors setup)

# Configure Flask logging immediately after creating the app instance
configure_logging(app) # <-- NEW CALL

# --- Database Models (SQLAlchemy) ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    tel = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    farms = db.relationship('Farm', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Farm(db.Model):
    __tablename__ = 'farms'
    id = db.Column(db.Integer, primary_key=True)
    farm_id_code = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    viewer = db.Column(db.Text, default='{}')   # {viewer_id: viewer_name}

    __table_args__ = (db.UniqueConstraint('user_id', 'farm_id_code', name='_user_farm_uc'),)
    
    devices = db.relationship('Device', backref='farm', lazy=True, cascade="all, delete-orphan")

    def share_farm(self):
        return self.viewer.split(" ")

    def to_dict(self):
        return {
            'id': self.id,
            'farm_id_code': self.farm_id_code,
            'name': self.name,
            'location': self.location,
            'user_id': self.user_id,
            'viewer': self.viewer
        }

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    device_id_code = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    farm_id_code = db.Column(db.String(20), db.ForeignKey('farms.farm_id_code'), nullable=False)

    config_json = db.Column(db.Text, default='[]')

    # device_id_code is unique per (user, farm)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'farm_id_code', 'device_id_code', name='_user_farm_device_uc'),
    )

    def to_dict(self):
        try:
            config_data = json.loads(self.config_json)
        except json.JSONDecodeError:
            config_data = []

        return {
            'id': self.id,
            'device_id_code': self.device_id_code,
            'type': self.type,
            'name': self.name,
            'farm_id_code': self.farm_id_code,
            'user_id': self.user_id,
            'config': config_data
        }

#--- SocketIO Handlers ---
@socketio.on('connect')
def handle_connect():
    app.logger.info("SocketIO Connected")

# --- MQTT Connection Handler ---
@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        # app.logger.info("✅ MQTT Client Connected successfully. Setting up subscriptions...")
        # CRITICAL: Place all your subscriptions here!
        mqtt.subscribe('farm/data/#')
        # app.logger.info("Subscribed to 'farm/data/#'")
    else:
         app.logger.info(f"❌ MQTT Connection failed with code {rc}. Flask-MQTT will retry.")

# --- MQTT Setup (Subscriber/Publisher) ---
@mqtt.on_message()
def handle_messages(client, userdata, message):
    topic = message.topic
    payload = message.payload.decode().split(',')
    
    # Example topic format: 'farm/FARM_A/TEMP_01/'
    
    try:
        # FIX: Changed topic_split to topic.split
        topic_parts = topic.split('/')
        
        # Expecting farm/sensor/FARM_ID/DEVICE_ID/
        if len(topic_parts) >= 2 or topic_parts[1] == 'sensor':
            farm_id_code = payload[1].split('=')[1]
            device_id_code = payload[2].split('=')[1]
            value = payload[3].split('=')[2] # Use raw payload if 'value' is missing
            username = payload[0]

            sending_payload = {
                    'farm_id_code': farm_id_code,
                    'device_id_code': device_id_code,
                    'value': value
                }
            socketio.emit('new_telemetry', sending_payload)
            # app.logger.info(f"MQTT Data received on topic '{topic}' with the message '{sending_payload}'and broadcast to SocketIO.")
            with app.app_context():
                sensor_device = Device.query.filter_by(farm_id_code=farm_id_code, device_id_code=device_id_code).first()
                current_config = json.loads(sensor_device.config_json)
                current_config["status"] = value
                sensor_device.config_json = json.dumps(current_config)
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    # app.logger.info(f"Database error during device update: {e}")
                    return jsonify({"error": "Internal server error during device update"}), 500
                
                app.logger.info("Testing timer devices")
                user = User.query.filter_by(username=username).first()                
                timer_devices = Device.query.filter(Device.config_json.contains('"mode": "timer"'), Device.user_id == user.id).all()

                app.logger.info("Timer Device Testing Completed")

                for device in timer_devices:
                    try:
                        # 1. Parse current config
                        current_config = json.loads(device.config_json)
                        previous_status = current_config.get("status", "-1")

                        # 2. Check if it SHOULD be on based on time logic
                        should_be_on = check_timer_condition(device)
                        new_status = "1" if should_be_on else "-1"

                        # 3. ONLY act if the status is changing
                        if new_status != previous_status:
                            # app.logger.info(f"Status change for {device.name}: {previous_status} -> {new_status}")
                            
                            # Update the dictionary and the DB field
                            current_config["status"] = new_status
                            device.config_json = json.dumps(current_config)

                            # MQTT Publish
                            topic = f'farm/commands/{username}/{device.farm_id_code}/{device.device_id_code}'
                            app.logger.info(topic)
                            mqtt.publish(topic, new_status, qos=1)

                            # Save to Database
                            db.session.commit()
                            sending_payload = {
                                    'farm_id_code': device.farm_id_code,
                                    'device_id_code': device.device_id_code,
                                    'value': new_status,
                                    'mode': 'timer'
                                }
                            socketio.emit('command', sending_payload, namespace='/')
                            # app.logger.info(f"Successfully updated {device.name} in DB.")
                        
                    except Exception as e:
                        db.session.rollback()
                        app.logger.error(f"Error processing device {device.device_id_code}: {e}")
                
                auto_devices = Device.query.filter(Device.config_json.contains('"mode": "auto"'), Device.user_id == user.id).all()
                for device in auto_devices:
                    try:
                        # 1. Parse current config
                        current_config = json.loads(device.config_json)
                        previous_status = current_config.get("status", "-1")

                        # 2. Check if it SHOULD be on based on time logic
                        feedback_device = Device.query.filter_by(device_id_code=current_config["feedback"]).first()
                        current_feedback = json.loads(feedback_device.config_json)
                        criteria = current_config["setting2"]
                        if(criteria == "น้อยกว่า"):
                            new_status = "1" if current_feedback["status"] < current_config["setting1"] else "-1"
                        elif(criteria == "เท่ากับ"):
                            new_status = "1" if current_feedback["status"]  == current_config["setting1"] else "-1"
                        else:
                            new_status = "1" if current_feedback["status"]  > current_config["setting1"] else "-1"

                        # 3. ONLY act if the status is changing
                        if new_status != previous_status:
                            # app.logger.info(f"Status change for {device.name}: {previous_status} -> {new_status}")
                            
                            # Update the dictionary and the DB field
                            current_config["status"] = new_status
                            device.config_json = json.dumps(current_config)

                            # MQTT Publish
                            topic = f'farm/commands/{username}/{device.farm_id_code}/{device.device_id_code}'
                            mqtt.publish(topic, new_status, qos=1)

                            # Save to Database
                            db.session.commit()
                            sending_payload = {
                                    'farm_id_code': device.farm_id_code,
                                    'device_id_code': device.device_id_code,
                                    'value': new_status,
                                    'mode': 'auto'
                                }
                            socketio.emit('command', sending_payload)
                            # app.logger.info(f"Successfully updated {device.name} in DB.")
                        
                    except Exception as e:
                        db.session.rollback()
                        app.logger.error(f"Error processing device {device.device_id_code}: {e}")
        else:
            # app.logger.info(f"MQTT Topic format invalid or not sensor/commands: {topic}")
            return # Exit if topic is not the expected format    

        # 2. Use SocketIO to push the data to the connected frontend clients

    except json.JSONDecodeError:
        app.logger.info(f"Error decoding JSON payload on topic {topic}")
    except Exception as e:
        app.logger.info(f"Unhandled error in MQTT message handler: {e}")

# --- Utility Function for Authentication ---

def require_auth(func):
    """
    Decorator to ensure user is logged in (via user_id in X-User-ID HTTP header).
    """
    def wrapper_func(*args, **kwargs):
        # 1. Get user_id from the X-User-ID HTTP header
        user_id_str = request.headers.get('X-User-ID')
        
        if not user_id_str:
            return jsonify({"error": "Authentication required. 'X-User-ID' header missing."}), 401
        
        try:
            user_id = int(user_id_str)
        except ValueError:
             return jsonify({"error": "Authentication required. Invalid 'X-User-ID' format."}), 401
             
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "Invalid user ID found in header."}), 401
        
        # 2. Safely extract JSON data for methods that DO expect a body (POST, PUT)
        data = request.get_json(silent=True)
        data = data if data is not None else {}
        
        # Pass the user object AND the data body to the wrapped function
        return func(user, data, *args, **kwargs)
    
    wrapper_func.__name__ = func.__name__ + '_auth_wrapper'
    return wrapper_func

# --- Initial Database Setup ---

def init_db():
    """Creates tables and a default user if the database is empty."""
    with app.app_context():
        # 1. Force table creation immediately upon application load.
        db.create_all()

        # Create a default test user, farm, and devices if none exists for easy testing
        if not User.query.first():
            # --- PHASE 1: Add Independent and Parent Records (User, Farm, Device) ---
            test_user = User(username='testuser', tel='0123456789')
            test_user.set_password('password')
            db.session.add(test_user)
            db.session.commit()

            test_farm = Farm(farm_id_code='FARM000T', name='Test Farm', user_id=1, viewer='0987654321')
            db.session.add(test_farm)
            db.session.commit()

            # Add Devices (Parents for DashboardPanel)
            test_device1 = Device(device_id_code='DEV001T', name='Test Temperature', type='เซ็นเซอร์', farm_id_code='FARM000T', config_json='' \
            '{"unit": "C", "color": "#cc1111", ' \
            '"mode": "ต่ำสุด-สูงสุด", "setting2": "50",' \
            '"status": "1"}')
            db.session.add(test_device1)
            test_device2 = Device(device_id_code='DEV000T', name='Test Humidity', type='เซ็นเซอร์', farm_id_code='FARM000T', config_json='' \
            '{"unit": "%", "color": "#11cc11", ' \
            '"mode": "ต่ำสุด-สูงสุด", "setting2": "100",' \
            '"status": "1"}')
            db.session.add(test_device2)
            test_device3 = Device(device_id_code='DEV010T', name='Test Moisture', type='เซ็นเซอร์', farm_id_code='FARM000T', config_json='' \
            '{"unit": "%", "color": "#1111cc", ' \
            '"mode": "ต่ำสุด-สูงสุด", "setting2": "100",' \
            '"status": "1"}')
            db.session.add(test_device3)
            test_device4 = Device(device_id_code='DEV005T', name='Test Pump', type='อุปกรณ์ขับ', farm_id_code='FARM000T', config_json='' \
            '{"unit": "", ' \
            '"mode": "manual",' \
            '"status": "-1"}')
            db.session.add(test_device4)
            test_device5 = Device(device_id_code='DEV006T', name='Test Valve 1', type='อุปกรณ์ขับ', farm_id_code='FARM000T', config_json='' \
            '{"unit": "", ' \
            '"mode": "timer", "setting1": "08.00", "setting2": "10", "setting3": "วินาที", "setting4": ["sun", "mon", "tue", "wed", "thu", "fri", "sat"],' \
            '"status": "-1"}')
            db.session.add(test_device5)
            test_device6 = Device(device_id_code='DEV007T', name='Test Valve 2', type='อุปกรณ์ขับ', farm_id_code='FARM000T', config_json='' \
            '{"unit": "", ' \
            '"mode": "auto", "setting1": "35", "setting2": "น้อยกว่า","feedback": "DEV002T",' \
            '"status": "-1"}')
            db.session.add(test_device6)
            test_device7 = Device(device_id_code='DEV008T', name='Test Valve 3', type='อุปกรณ์ขับ', farm_id_code='FARM000T', config_json='' \
            '{"unit": "", ' \
            '"mode": "manual",' \
            '"status": "-1"}')
            db.session.add(test_device7)
            
            # Commit/Flush Phase 1: Ensure all devices are written to the database 
            # so the Foreign Key check in the next phase passes.
            db.session.commit()
            # app.logger.info("Default test user 'testuser' created (ID: 1) along with test farm, devices, and panels.")

init_db()

@app.route('/main')
def index():
    return render_template('custom_farm_manager.html')

# --- API Routes ---

@app.route('/api/v1/status', methods=['GET'])
def get_status():
    return jsonify({"status": "ok", "message": "Smart Farm API is running!"}), 200

# ----------------------------------------------------
# User Registration and Login (No change)
# ----------------------------------------------------

@app.route('/api/v1/users/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    tel = data.get('tel')
    password = data.get('password')

    if not all([username, tel, password]):
        return jsonify({"error": "Missing username, tel no., or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409
    
    if User.query.filter_by(tel=tel).first():
        return jsonify({"error": "Telephone already registered"}), 409

    new_user = User(username=username, tel=tel)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            "message": "User registered successfully", 
            "user_id": new_user.id
        }), 201
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during registration: {e}")
        return jsonify({"error": "Internal server error during registration"}), 500

@app.route('/api/v1/users/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        return jsonify({
            "message": "Login successful",
            "user_id": user.id,
            "username": user.username
        }), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401
    
@app.route('/api/v1/users/change', methods=['PUT'])
@require_auth
def change_password(user, data):
    username = data.get('username')
    new_password = data.get('new_password')

    user = User.query.filter_by(username=username).first()
    if username==user.username:
        user.set_password(new_password)

    try:
        db.session.commit()
        return jsonify({
            "message": "Changed password successfully",
            "user": username
        }), 200
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during password changing: {e}")
        return jsonify({"error": "Internal server error during password changing"}), 500

# ----------------------------------------------------
# Farm Management (CRUD - No change to logic)
# ----------------------------------------------------

@app.route('/api/v1/farms', methods=['POST'])
@require_auth
def list_farms(user, data):
    farms = Farm.query.filter_by(user_id=user.id).all()
    sharedFarms = []
    for f in Farm.query.all():
        if user.tel in f.share_farm():
            sharedFarms.append(f)
#    sharedFarms = Farm.query.filter(Farm.viewer.contains(user.username)).all()
    return jsonify({"farms": [f.to_dict() for f in farms],
                    "sharedFarms": [sf.to_dict() for sf in sharedFarms]}), 200

@app.route('/api/v1/farms/create', methods=['POST'])
@require_auth
def create_farm(user, data):
    farm_id_code = data.get('farm_id_code')
    name = data.get('name')
    location = data.get('location')
    viewer = data.get('viewer')

    if not all([farm_id_code, name]):
        return jsonify({"error": "Missing farm_id_code or name"}), 400

    if Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first():
        return jsonify({"error": f"Farm ID '{farm_id_code}' already exists for this user."}), 409

    new_farm = Farm(
        farm_id_code=farm_id_code,
        name=name,
        location=location,
        user_id=user.id,
        viewer=viewer
    )

    try:
        db.session.add(new_farm)
        db.session.commit()
        return jsonify({
            "message": "Farm created successfully",
            "farm": new_farm.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during farm creation: {e}")
        return jsonify({"error": "Internal server error during farm creation"}), 500
    

@app.route('/api/v1/farms/<int:farm_db_id>', methods=['PUT'])
@require_auth
def update_farm(user, data, farm_db_id):
    farm_id_code = data.get('farm_id_code')
    farm = Farm.query.filter_by(farm_id_code=farm_id_code, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Farm not found or access denied."}), 404

    farm.name = data.get('name', farm.name)
    farm.location = data.get('location', farm.location)
    farm.viewer = data.get('viewer', farm.viewer)
    
    try:
        db.session.commit()
        return jsonify({
            "message": "Farm updated successfully",
            "farm": farm.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during farm update: {e}")
        return jsonify({"error": "Internal server error during farm update"}), 500

# Using POST for delete, as requested by user
@app.route('/api/v1/farms/<int:farm_db_id>/delete', methods=['POST'])
@require_auth
def delete_farm(user, data, farm_db_id):
    farm_id_code = data.get('farm_id_code')
    farm = Farm.query.filter_by(farm_id_code=farm_id_code, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Farm not found or access denied."}), 404

    try:
        db.session.delete(farm)
        db.session.commit()
        return jsonify({"message": f"Farm '{farm.name}' deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during farm deletion: {e}")
        return jsonify({"error": "Internal server error during farm deletion"}), 500

# ----------------------------------------------------
# Device Management (CRUD - No change to logic)
# ----------------------------------------------------

@app.route('/api/v1/devices', methods=['POST'])
@require_auth
def get_devices(user, data):
    farm_id_code = data.get('farm_id_code')
    
    if not farm_id_code:
        return jsonify({"error": "Missing 'farm_id_code' in request body."}), 400

    farm = Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first()
    
    # if not (farm or user.tel in (Farm.query.filter_by(farm_id_code=farm_id_code).first().share_farm())):
    #     return jsonify({"error": "Farm not found or access denied."}), 404
    sharedFarm = Farm.query.filter(Farm.farm_id_code == farm_id_code, Farm.viewer.contains(user.tel)).first()

    if farm:
        devices = Device.query.filter_by(farm_id_code=farm.farm_id_code).all()
        return jsonify([device.to_dict() for device in devices]), 200
    elif sharedFarm:
        sharedDevices = Device.query.filter_by(farm_id_code=sharedFarm.farm_id_code).all()
        return jsonify([device.to_dict() for device in sharedDevices]), 200
    else:
        return jsonify({"error": "Farm not found or access denied."}), 404
    
    # devices = Device.query.filter_by(farm_id_code=farm.farm_id_code).all()
    
    # return jsonify({"devices": [d.to_dict() for d in devices]}), 200


@app.route('/api/v1/devices/create', methods=['POST'])
@require_auth
def create_device(user, data):
    farm_id_code = data.get('farm_id_code')
    device_id_code = data.get('device_id_code')
    device_type = data.get('type')
    user_id = data.get('user_id')
    name = data.get('name')
    config = json.dumps(data.get('config', {}))

    if not all([farm_id_code, device_id_code, device_type, name]):
        return jsonify({"error": "Missing required fields (farm_id_code, device_id_code, type, name)"}), 400

    farm = Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first()
    if not farm:
        return jsonify({"error": "Target farm not found or access denied."}), 404

    if Device.query.filter_by(farm_id_code=farm.farm_id_code, device_id_code=device_id_code).first():
        return jsonify({"error": f"Device ID '{device_id_code}' already exists in farm '{farm_id_code}'."}), 409

    new_device = Device(
        device_id_code=device_id_code,
        type=device_type,
        name=name,
        farm_id_code=farm_id_code,
        config_json=config,
        user_id=user_id
    )

    try:
        db.session.add(new_device)
        db.session.commit()
        
        return jsonify({
            "message": "Device created successfully",
            "device": new_device.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during device creation: {e}")
        return jsonify({"error": "Internal server error during device creation"}), 500

@app.route('/api/v1/devices/<int:device_db_id>', methods=['PUT'])
@require_auth
def update_device(user, data, device_db_id):
    device = Device.query.filter_by(id=device_db_id).first()
    if not device:
        return jsonify({"error": "Device not found."}), 404

    farm = Farm.query.filter_by(farm_id_code=device.farm_id_code, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Access denied. You do not own this device's farm."}), 403

    device.type = data.get('type', device.type)
    device.name = data.get('name', device.name)
    if 'config' in data:
        device.config_json = json.dumps(data['config'])
    
    try:
        db.session.commit()
        return jsonify({
            "message": "Device updated successfully",
            "device": device.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during device update: {e}")
        return jsonify({"error": "Internal server error during device update"}), 500

# Using POST for delete, as requested by user
@app.route('/api/v1/devices/<int:device_db_id>/delete', methods=['POST'])
@require_auth
def delete_device(user, data, device_db_id):
    device_id_code = data.get('device_id_code')
    device = Device.query.filter_by(device_id_code=device_id_code).first()
    if not device:
        return jsonify({"error": "Device not found."}), 404
        
    farm = Farm.query.filter_by(farm_id_code=device.farm_id_code, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Access denied. You do not own this device's farm."}), 403

    try:
        db.session.delete(device)
        db.session.commit()
        return jsonify({"message": f"Device '{device.name}' deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        # app.logger.info(f"Database error during device deletion: {e}")
        return jsonify({"error": "Internal server error during device deletion"}), 500

# ----------------------------------------------------
# Control Endpoint (Pump)
# ----------------------------------------------------

# 3. API Endpoint to Send Commands (From server to devices)
@app.route('/api/v1/devices/control', methods=['POST'])
@require_auth
def send_device_command(user, data):
    # Ensure the user owns the device before sending a command (security check)
    
    command = data.get('command') # e.g., 'PUMP_ON', 'PUMP_OFF'
    username = data.get('username')
    device_id_code = data.get('device_id_code')
    farm_id_code = data.get('farm_id_code')

    device = Device.query.filter_by(farm_id_code=farm_id_code, device_id_code=device_id_code).first()
    
    # Topic format for commands: 'commands/FARM000/DEV001/pump'

    if not command:
        return jsonify({"error": "Missing 'command' parameter."}), 400
    try:
        # 1. Parse current config
        current_config = json.loads(device.config_json)
        previous_status = current_config.get("status", "-1")

        # 2. Check if it SHOULD be on based on time logic
        new_status = command

        # 3. ONLY act if the status is changing
        if new_status != previous_status:
            # app.logger.info(f"Status change for {device.name}: {previous_status} -> {new_status}")
            
            # Update the dictionary and the DB field
            current_config["status"] = new_status
            device.config_json = json.dumps(current_config)

            # MQTT Publish
            topic = f'farm/commands/{username}/{device.farm_id_code}/{device.device_id_code}'
            mqtt.publish(topic, new_status, qos=1)

            # Save to Database
            db.session.commit()
            # app.logger.info(f"Successfully updated {device.name} in DB.")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error processing device {device.device_id_code}: {e}")
    # Publish the command over MQTT
    
    return jsonify({"message": f"Command '{command}' sent to {device_id_code}."}), 200

def check_timer_condition(device):
    # Parse the config string into a dictionary
    config = json.loads(device.config_json)
    
    if config.get("mode") != "timer":
        return False

    now = datetime.now(tz=timezone(timedelta(hours=7)))
    # Get current day in lowercase 'mon', 'tue', etc.
    current_day = now.strftime("%a").lower() 
    
    # 1. Check if today is an active day
    active_days = config.get("setting4", [])
    if current_day not in active_days:
        return False

    # 2. Parse Start Time (setting1: "08.00")
    try:
        start_time_str = config.get("setting1")
        # Converting "08.00" to a time object
        start_time = datetime.strptime(start_time_str, "%H.%M").time()
        # Create a datetime for today at that start time
        start_dt = now.replace(hour=start_time.hour, minute=start_time.minute, second=0, microsecond=0)
    except ValueError:
        return False

    # 3. Calculate Duration (setting2 and setting3)
    duration = int(config.get("setting2", 0))
    unit = config.get("setting3") # "วินาที" (seconds) or "นาที" (minutes)
    
    if unit == "วินาที":
        end_dt = start_dt + timedelta(seconds=duration)
    elif unit == "นาที":
        end_dt = start_dt + timedelta(minutes=duration)
    elif unit == "ชั่วโมง":
        end_dt = start_dt + timedelta(hours=duration)
    else:
        return False

    # 4. Final Verdict: Is 'now' between start and end?
    return start_dt <= now <= end_dt

# @scheduler.task('interval', id='check_pumps', seconds=5)
# def monitor_pumps():
    

socketio_app = socketio 
socketio.run(app, host='0.0.0.0', port=5000, debug=False)
# if __name__ == '__main__':
#     # When running locally, the init_db() call above will create tables/user.
#     # We simply run the socketio app.
#     socketio.run(app, host='0.0.0.0', port=5000, debug=True)
