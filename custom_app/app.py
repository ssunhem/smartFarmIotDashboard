import os
import json
import eventlet
import logging
import sys

from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS 
from flask_mqtt import Mqtt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO

eventlet.monkey_patch()

# --- Configuration ---
# Database (SQLite file inside the Docker container)
db_uri = 'sqlite:////tmp/app.db'

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_secret_key_for_dev')

db = SQLAlchemy(app)
CORS(app) # Initialize CORS with the Flask app
# app.config['MQTT_CLIENT_ID'] = 'gunicorn-worker-' + os.urandom(8).hex()
topic_base = "farm" # Base topic for control and telemetry

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

# ... (Existing app, db, and cors setup)

# Configure Flask logging immediately after creating the app instance
configure_logging(app) # <-- NEW CALL

# --- Database Models (SQLAlchemy) ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
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

    __table_args__ = (db.UniqueConstraint('user_id', 'farm_id_code', name='_user_farm_uc'),)
    
    devices = db.relationship('Device', backref='farm', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'farm_id_code': self.farm_id_code,
            'name': self.name,
            'location': self.location,
            'user_id': self.user_id
        }

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    device_id_code = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(50), nullable=False) # e.g., 'Sensor', 'Actuator'
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100))
    farm_id = db.Column(db.Integer, db.ForeignKey('farms.id'), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('farm_id', 'device_id_code', name='_farm_device_uc'),)

    def to_dict(self):
        return {
            'id': self.id,
            'device_id_code': self.device_id_code,
            'type': self.type,
            'name': self.name,
            'location': self.location,
            'farm_id': self.farm_id
        }
    
class DashboardPanel(db.Model):
    __tablename__ = 'dashboard_panels'
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key linking the panel to the User who owns it (mandatory)
    farm_id = db.Column(db.Integer, db.ForeignKey('farms.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id_code'), nullable=False)
    # Panel display information
    panel_id_code = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(20), nullable=False) # e.g., 'LineChart', 'Gauge', 'Button'
    
    # Store arbitrary configuration data (e.g., axis ranges, colors, button topics) as JSON text
    config_json = db.Column(db.Text, default='{}')

    # Optional: Define a relationship back to the User model if needed
    # owner = db.relationship('User', backref='dashboard_panels', lazy=True)

    def to_dict(self):
        """Returns a dictionary representation for API serialization."""
        try:
            config_data = json.loads(self.config_json)
        except json.JSONDecodeError:
            config_data = {} # Fallback if JSON is invalid

        return {
            'id': self.id,
            'panel_id_code': self.panel_id_code,
            'name': self.name,
            'type': self.type,
            'farm_id': self.farm_id,
            'device_id': self.device_id,
            'config': config_data
        }
    
    def __repr__(self):
        return f'<DashboardPanel {self.id}: {self.name} ({self.type})>'

#--- SocketIO Handlers ---
@socketio.on('connect')
def handle_connect():
    app.logger.info("SocketIO Connected")

# --- MQTT Connection Handler ---
@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    if rc == 0:
        app.logger.info("✅ MQTT Client Connected successfully. Setting up subscriptions...")
        # CRITICAL: Place all your subscriptions here!
        mqtt.subscribe('farm/data/#')
        app.logger.info("Subscribed to 'farm/data/#'")
    else:
        app.logger.info(f"❌ MQTT Connection failed with code {rc}. Flask-MQTT will retry.")

# --- MQTT Setup (Subscriber/Publisher) ---
@mqtt.on_message()
def handle_messages(client, userdata, message):
    topic = message.topic
    payload = message.payload.decode()
    
    # Example topic format: 'farm/FARM_A/TEMP_01/PAN001'
    
    try:
        # FIX: Changed topic_split to topic.split
        topic_parts = topic.split('/')
        
        # Expecting farm/telemetry/FARM_ID/DEVICE_ID/SENSOR_TYPE
        if len(topic_parts) < 5 or topic_parts[1] not in ['telemetry', 'status']:
            app.logger.info(f"MQTT Topic format invalid or not telemetry/status: {topic}")
            return # Exit if topic is not the expected format

        farm_id = topic_parts[2] 
        device_id_code = topic_parts[3] 
        panel_id_code = topic_parts[4] # e.g., temperature, humidity, pump/1

        telemetry_data = json.loads(payload)

        # 1. Extract key value for real-time update
        value = telemetry_data.get('value', payload) # Use raw payload if 'value' is missing

        # 2. Use SocketIO to push the data to the connected frontend clients
        sending_payload = {
                'farm_id': farm_id,
                'device_id_code': device_id_code,
                'panel_id_code': panel_id_code,
                'value': value,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        socketio.emit('new_telemetry', sending_payload )
        
        app.logger.info(f"MQTT Data received on topic '{topic}' with the message '{sending_payload}'and broadcast to SocketIO.")

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
        # Force table creation immediately upon application load.
        db.create_all()

        # Create a default test user if none exists for easy testing
        if not User.query.first():
            test_user = User(username='testuser', email='test@example.com')
            test_user.set_password('password')
            db.session.add(test_user)
            db.session.commit()
            app.logger.info("Default test user 'testuser' created (ID: 1).")

# Call the initialization function here so it runs when Gunicorn preloads the app
init_db()

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
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({"error": "Missing username, email, or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    new_user = User(username=username, email=email)
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
        app.logger.info(f"Database error during registration: {e}")
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

# ----------------------------------------------------
# Farm Management (CRUD - No change to logic)
# ----------------------------------------------------

@app.route('/api/v1/farms', methods=['POST'])
@require_auth
def list_farms(user, data):
    farms = Farm.query.filter_by(user_id=user.id).all()
    return jsonify({"farms": [f.to_dict() for f in farms]}), 200


@app.route('/api/v1/farms/create', methods=['POST'])
@require_auth
def create_farm(user, data):
    farm_id_code = data.get('farm_id_code')
    name = data.get('name')
    location = data.get('location')

    if not all([farm_id_code, name]):
        return jsonify({"error": "Missing farm_id_code or name"}), 400

    if Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first():
        return jsonify({"error": f"Farm ID '{farm_id_code}' already exists for this user."}), 409

    new_farm = Farm(
        farm_id_code=farm_id_code,
        name=name,
        location=location,
        user_id=user.id
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
        app.logger.info(f"Database error during farm creation: {e}")
        return jsonify({"error": "Internal server error during farm creation"}), 500
    

@app.route('/api/v1/farms/<int:farm_db_id>', methods=['PUT'])
@require_auth
def update_farm(user, data, farm_db_id):
    farm = Farm.query.filter_by(id=farm_db_id, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Farm not found or access denied."}), 404

    farm.name = data.get('name', farm.name)
    farm.location = data.get('location', farm.location)
    
    try:
        db.session.commit()
        return jsonify({
            "message": "Farm updated successfully",
            "farm": farm.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.info(f"Database error during farm update: {e}")
        return jsonify({"error": "Internal server error during farm update"}), 500

# Using POST for delete, as requested by user
@app.route('/api/v1/farms/<int:farm_db_id>/delete', methods=['POST'])
@require_auth
def delete_farm(user, data, farm_db_id):
    farm = Farm.query.filter_by(id=farm_db_id, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Farm not found or access denied."}), 404

    try:
        db.session.delete(farm)
        db.session.commit()
        return jsonify({"message": f"Farm '{farm.name}' deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.info(f"Database error during farm deletion: {e}")
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
    
    if not farm:
        return jsonify({"error": "Farm not found or access denied."}), 404
    
    devices = Device.query.filter_by(farm_id=farm.id).all()
    
    return jsonify({"devices": [d.to_dict() for d in devices]}), 200


@app.route('/api/v1/devices/create', methods=['POST'])
@require_auth
def create_device(user, data):
    farm_id_code = data.get('farm_id_code')
    device_id_code = data.get('device_id_code')
    device_type = data.get('type')
    name = data.get('name')
    location = data.get('location')

    if not all([farm_id_code, device_id_code, device_type, name]):
        return jsonify({"error": "Missing required fields (farm_id_code, device_id_code, type, name)"}), 400

    farm = Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first()
    if not farm:
        return jsonify({"error": "Target farm not found or access denied."}), 404

    if Device.query.filter_by(farm_id=farm.id, device_id_code=device_id_code).first():
        return jsonify({"error": f"Device ID '{device_id_code}' already exists in farm '{farm_id_code}'."}), 409

    new_device = Device(
        device_id_code=device_id_code,
        type=device_type,
        name=name,
        location=location,
        farm_id=farm.id
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
        app.logger.info(f"Database error during device creation: {e}")
        return jsonify({"error": "Internal server error during device creation"}), 500

@app.route('/api/v1/devices/<int:device_db_id>', methods=['PUT'])
@require_auth
def update_device(user, data, device_db_id):
    device = Device.query.filter_by(id=device_db_id).first()
    if not device:
        return jsonify({"error": "Device not found."}), 404

    farm = Farm.query.filter_by(id=device.farm_id, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Access denied. You do not own this device's farm."}), 403

    device.type = data.get('type', device.type)
    device.name = data.get('name', device.name)
    device.location = data.get('location', device.location)
    
    try:
        db.session.commit()
        return jsonify({
            "message": "Device updated successfully",
            "device": device.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.info(f"Database error during device update: {e}")
        return jsonify({"error": "Internal server error during device update"}), 500

# Using POST for delete, as requested by user
@app.route('/api/v1/devices/<int:device_db_id>/delete', methods=['POST'])
@require_auth
def delete_device(user, data, device_db_id):
    device = Device.query.filter_by(id=device_db_id).first()
    if not device:
        return jsonify({"error": "Device not found."}), 404
        
    farm = Farm.query.filter_by(id=device.farm_id, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Access denied. You do not own this device's farm."}), 403

    try:
        db.session.delete(device)
        db.session.commit()
        return jsonify({"message": f"Device '{device.name}' deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.info(f"Database error during device deletion: {e}")
        return jsonify({"error": "Internal server error during device deletion"}), 500
    

# ----------------------------------------------------
# Panel Management (CRUD - No change to logic)
# ----------------------------------------------------
    
@app.route('/api/v1/panels', methods=['POST'])
@require_auth
def get_panels(user, data):
    """Returns all panels belonging to the authenticated user."""
    farm_id_code = data.get('farm_id_code')

    if not farm_id_code:
        return jsonify({"error": "Missing 'farm_id_code' in request body."}), 400
    
    farm = Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first()
    
    if not farm:
        return jsonify({"error": "Farm not found or access denied."}), 404

    panels = DashboardPanel.query.filter_by(farm_id=farm.id).all()
    return jsonify([panel.to_dict() for panel in panels]), 200

@app.route('/api/v1/panels/create', methods=['POST'])
@require_auth
def create_panel(user, data):
    panel_id_code = data.get('panel_id_code')
    panel_type = data.get('type')
    name = data.get('name')
    farm_id_code = data.get('farm_id_code')
    device_id_code = data.get('device_id_code')
    config = json.dumps(data.get('config', {}))

    if not all([panel_id_code, panel_type, name, device_id_code, farm_id_code]):
        return jsonify({"error": "Missing required fields (panel_id_code, panel_type, name, device_id_code, farm_id_code)"}), 400
    
    farm = Farm.query.filter_by(user_id=user.id, farm_id_code=farm_id_code).first()
    if not farm:
        return jsonify({"error": "Target farm not found or access denied."}), 404

    device = Device.query.filter_by(farm_id=farm.id, device_id_code=device_id_code).first()
    if not farm:
        return jsonify({"error": "Target device not found or access denied."}), 404

    if DashboardPanel.query.filter_by(farm_id=farm.id, device_id=device_id_code, panel_id_code=panel_id_code).first():
        return jsonify({"error": f"Device ID '{panel_id_code}' already exists in farm '{panel_id_code}'."}), 409

    new_panel = DashboardPanel(
        panel_id_code=panel_id_code,
        name=name,
        type=panel_type,
        farm_id=farm.id,
        device_id=device.id,
        config_json=config
    )
    
    try:
        db.session.add(new_panel)
        db.session.commit()
        
        return jsonify({
            "message": "Panel created successfully",
            "device": new_panel.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.info(f"Database error during panel creation: {e}")
        return jsonify({"error": "Internal server error during panel creation"}), 500

@app.route('/api/v1/panels/<int:panel_id>', methods=['PUT'])
@require_auth
def update_panel(user, data, panel_id):
    """Updates an existing panel, ensuring ownership."""
    panel = DashboardPanel.query.get(panel_id)

    if not panel:
        return jsonify({"error": "Panel not found."}), 404
    
    farm = Farm.query.filter_by(id=panel.farm_id, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Access denied. You do not own this device's farm."}), 403

        
    panel.name = data.get('name', panel.name)
    panel.type = data.get('type', panel.type)
    panel.device_id = data.get('device_id_code', panel.device_id)
    
    if 'config' in data:
        panel.config_json = json.dumps(data['config'])
        
    db.session.commit()
    return jsonify(panel.to_dict())

@app.route('/api/v1/panels/<int:panel_id>/delete', methods=['POST'])
@require_auth
def delete_panel(user, data, panel_id):
    """Deletes an existing panel, ensuring ownership."""
    panel = DashboardPanel.query.get(panel_id)

    if not panel:
        return jsonify({"error": "Panel not found."}), 404
        
    farm = Farm.query.filter_by(id=panel.farm_id, user_id=user.id).first()
    if not farm:
        return jsonify({"error": "Access denied. You do not own this device's farm."}), 403

    db.session.delete(panel)
    db.session.commit()
    return jsonify({"message": f"Panel {panel_id} deleted successfully."}), 200

# ----------------------------------------------------
# Control Endpoint (Pump)
# ----------------------------------------------------

# 3. API Endpoint to Send Commands (From server to devices)
@app.route('/api/v1/devices/<string:device_id_code>/control', methods=['POST'])
@require_auth
def send_device_command(user, data, device_id_code):
    # Ensure the user owns the device before sending a command (security check)
    
    command = data.get('command') # e.g., 'PUMP_ON', 'PUMP_OFF'
    device_id = data.get('device_id')
    
    # Topic format for commands: 'commands/DEV001/pump'
    command_topic = f'commands/{device_id}/actuator' 

    if not command:
        return jsonify({"error": "Missing 'command' parameter."}), 400
    
    # Publish the command over MQTT
    mqtt.publish(command_topic, command, qos=1) 
    
    return jsonify({"message": f"Command '{command}' sent to {device_id_code}."}), 200

socketio_app = socketio 
socketio.run(app, host='0.0.0.0', port=5000, debug=False)
# if __name__ == '__main__':
#     # When running locally, the init_db() call above will create tables/user.
#     # We simply run the socketio app.
#     socketio.run(app, host='0.0.0.0', port=5000, debug=True)