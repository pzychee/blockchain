import hashlib
import json
import time
import uuid
import re
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-key-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blockchain_payment.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Change in production
app.config['MAIL_PASSWORD'] = 'your-password'         # Change in production
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@blockchain-payment.com'
app.config['BLOCKCHAIN_DIFFICULTY'] = 4  # PoW difficulty level

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
 
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)

# -------------------------
# Database Models
# -------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    payment_pin_hash = db.Column(db.String(128), nullable=False)
    payment_id = db.Column(db.String(16), unique=True, nullable=False)
    balance = db.Column(db.Float, default=100000.0) 
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_payment_pin(self, pin):
        self.payment_pin_hash = generate_password_hash(pin)

    def check_payment_pin(self, pin):
        return check_password_hash(self.payment_pin_hash, pin)

    def generate_payment_id(self):
        # Generate a random 16-digit number
        digits = string.digits
        self.payment_id = ''.join(secrets.choice(digits) for _ in range(16))
        return self.payment_id


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(16), nullable=False)
    recipient_id = db.Column(db.String(16), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="pending")  # pending, completed, failed
    transaction_hash = db.Column(db.String(64), nullable=False)
    block_number = db.Column(db.Integer, nullable=True)


class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    block_number = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transactions = db.Column(db.Text, nullable=False)  # JSON string of transactions
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    difficulty = db.Column(db.Integer, nullable=False)
    is_valid = db.Column(db.Boolean, default=True)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------
# Blockchain Implementation
# -------------------------

class Blockchain:
    def __init__(self):
        # Initialize blockchain or get the latest from database
        latest_block = Block.query.order_by(Block.block_number.desc()).first()
        if not latest_block:
            # Create genesis block if blockchain is empty
            self.create_genesis_block()
        
    def create_genesis_block(self):
        """Create the genesis block with no previous hash"""
        genesis_block = Block(
            block_number=0,
            transactions=json.dumps([]),
            previous_hash="0" * 64,
            hash=self.calculate_hash(0, "0" * 64, [], 0, datetime.utcnow()),
            nonce=0,
            difficulty=app.config['BLOCKCHAIN_DIFFICULTY'],
            timestamp=datetime.utcnow()
        )
        db.session.add(genesis_block)
        db.session.commit()
        return genesis_block
    
    def get_latest_block(self):
        """Get the latest block from the database"""
        return Block.query.order_by(Block.block_number.desc()).first()
    
    def calculate_hash(self, block_number, previous_hash, transactions, nonce, timestamp):
        """Calculate SHA-256 hash of the block"""
        block_string = f"{block_number}{previous_hash}{json.dumps(transactions)}{nonce}{timestamp}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def proof_of_work(self, block_number, previous_hash, transactions, timestamp):
        """Proof of Work algorithm"""
        nonce = 0
        difficulty = app.config['BLOCKCHAIN_DIFFICULTY']
        target = "0" * difficulty
        
        while True:
            hash = self.calculate_hash(block_number, previous_hash, transactions, nonce, timestamp)
            if hash[:difficulty] == target:
                return nonce, hash
            nonce += 1
    
    def add_block(self, transactions):
        """Add a new block to the blockchain with the given transactions"""
        latest_block = self.get_latest_block()
        block_number = latest_block.block_number + 1
        previous_hash = latest_block.hash
        timestamp = datetime.utcnow()
        
        # Perform proof of work
        nonce, hash = self.proof_of_work(block_number, previous_hash, transactions, timestamp)
        
        # Create new block
        new_block = Block(
            block_number=block_number,
            transactions=json.dumps(transactions),
            previous_hash=previous_hash,
            hash=hash,
            nonce=nonce,
            difficulty=app.config['BLOCKCHAIN_DIFFICULTY'],
            timestamp=timestamp
        )
        
        db.session.add(new_block)
        db.session.commit()
        
        # Update transactions with block number
        for tx_data in transactions:
            tx = Transaction.query.filter_by(transaction_hash=tx_data['transaction_hash']).first()
            if tx:
                tx.block_number = block_number
                tx.status = "completed"
        
        db.session.commit()
        return new_block
    
    def verify_chain(self):
        """Verify the integrity of the blockchain"""
        blocks = Block.query.order_by(Block.block_number).all()
        
        for i in range(1, len(blocks)):
            current = blocks[i]
            previous = blocks[i-1]
            
            # Check if the previous hash reference is correct
            if current.previous_hash != previous.hash:
                return False
            
            # Check if the block's hash is valid
            transactions = json.loads(current.transactions)
            calculated_hash = self.calculate_hash(
                current.block_number, 
                current.previous_hash, 
                transactions, 
                current.nonce, 
                current.timestamp
            )
            
            if calculated_hash != current.hash:
                return False
            
            # Check if the hash meets the difficulty requirement
            if current.hash[:current.difficulty] != "0" * current.difficulty:
                return False
        
        return True

# -------------------------
# Authentication Functions
# -------------------------

def generate_token(user_id):
    """Generate JWT token for authenticated users"""
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

def token_required(f):
    """Decorator for routes that require JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Validate token
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['sub'])
            if not current_user:
                return jsonify({'message': 'Invalid token'}), 401
        except:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def login_required(f):
    """Decorator for routes that require session authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

 

# -------------------------
# Helper Functions
# -------------------------

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
        return False
    return True

def validate_pin(pin):
    """Validate PIN format (6 digits)"""
    return pin.isdigit() and len(pin) == 6

def create_transaction(sender_id, recipient_id, amount):
    """Create a new transaction"""
    transaction_data = {
        'sender_id': sender_id,
        'recipient_id': recipient_id,
        'amount': amount,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Generate transaction hash
    transaction_string = json.dumps(transaction_data, sort_keys=True)
    transaction_hash = hashlib.sha256(transaction_string.encode()).hexdigest()
    transaction_data['transaction_hash'] = transaction_hash
    
    # Create transaction record
    transaction = Transaction(
        sender_id=sender_id,
        recipient_id=recipient_id,
        amount=amount,
        transaction_hash=transaction_hash
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return transaction

def create_notification(user_id, message):
    """Create a notification for user"""
    notification = Notification(
        user_id=user_id,
        message=message
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def process_transactions():
    """Process pending transactions and add them to the blockchain"""
    pending_transactions = Transaction.query.filter_by(status="pending").all()
    
    if pending_transactions:
        # Prepare transactions for the block
        transactions_data = []
        for tx in pending_transactions:
            transactions_data.append({
                'sender_id': tx.sender_id,
                'recipient_id': tx.recipient_id,
                'amount': tx.amount,
                'timestamp': tx.timestamp.isoformat(),
                'transaction_hash': tx.transaction_hash
            })
        
        # Add block to blockchain
        blockchain = Blockchain()
        blockchain.add_block(transactions_data)
        
        # Notify users about the transactions
        for tx in pending_transactions:
            # Notify sender
            sender = User.query.filter_by(payment_id=tx.sender_id).first()
            if sender:
                create_notification(
                    sender.id, 
                    f"Your payment of {tx.amount} to {tx.recipient_id} has been processed."
                )
            
            # Notify recipient
            recipient = User.query.filter_by(payment_id=tx.recipient_id).first()
            if recipient:
                create_notification(
                    recipient.id, 
                    f"You received {tx.amount} from {tx.sender_id}."
                )

def update_user_balances():
    users = User.query.all()
    for user in users:
        user.balance = 100000.0
    db.session.commit()
    update_user_balances()
# -------------------------
# Routes - Web Interface
# -------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        payment_pin = request.form.get('payment_pin')
        
        # Validate inputs
        if not all([email, password, confirm_password, payment_pin]):
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if not validate_email(email):
            flash('Invalid email format', 'error')
            return render_template('register.html')
        
        if not validate_password(password):
            flash('Password must be at least 8 characters and contain both letters and numbers', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        if not validate_pin(payment_pin):
            flash('PIN must be 6 digits', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(email=email)
        user.set_password(password)
        user.set_payment_pin(payment_pin)
        user.generate_payment_id()
        user.balance = 100000.0  # Explicitly set the balance to 100,000
        
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        flash('Invalid or expired verification token', 'error')
        return redirect(url_for('login'))
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([email, password]):
            flash('Email and password are required', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Invalid email or password', 'error')
            return render_template('login.html')
        
 
        
        # Update last login time
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Create session
        session['user_id'] = user.id
        
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # Get recent transactions
    sent_transactions = Transaction.query.filter_by(sender_id=user.payment_id).order_by(Transaction.timestamp.desc()).limit(5).all()
    received_transactions = Transaction.query.filter_by(recipient_id=user.payment_id).order_by(Transaction.timestamp.desc()).limit(5).all()
    
    # Combine and sort transactions
    recent_transactions = []
    for tx in sent_transactions + received_transactions:
        # Classify transaction type
        if tx.sender_id == user.payment_id:
            tx_type = 'sent'
            other_user = tx.recipient_id
        else:
            tx_type = 'received'
            other_user = tx.sender_id
            
        # Get transaction status
        status = tx.status
        if status == 'pending':
            status = 'Pending'
        elif status == 'completed':
            status = 'Completed'
        else:
            status = 'Failed'
            
        recent_transactions.append({
            'id': tx.id,
            'type': tx_type,
            'amount': tx.amount,
            'other_user': other_user,
            'timestamp': tx.timestamp,
            'status': status,
            'transaction_hash': tx.transaction_hash
        })
    
    # Sort transactions by timestamp
    recent_transactions.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get unread notifications
    notifications = Notification.query.filter_by(user_id=user_id, is_read=False).order_by(Notification.created_at.desc()).all()
    
    return render_template(
        'dashboard.html', 
        user=user,
        recent_transactions=recent_transactions[:5],  # Show only last 5 transactions
        notifications=notifications
    )

@app.route('/send_payment', methods=['GET', 'POST'])
@login_required
def send_payment():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id')
        amount = request.form.get('amount')
        payment_pin = request.form.get('payment_pin')
        
        try:
            amount = float(amount)
        except ValueError:
            flash('Invalid amount', 'error')
            return render_template('send_payment.html', user=user)
        
        # Validate inputs
        if not all([recipient_id, amount, payment_pin]):
            flash('All fields are required', 'error')
            return render_template('send_payment.html', user=user)
        
        if amount <= 0:
            flash('Amount must be greater than zero', 'error')
            return render_template('send_payment.html', user=user)
        
        if user.balance < amount:
            flash('Insufficient balance', 'error')
            return render_template('send_payment.html', user=user)
        
        if recipient_id == user.payment_id:
            flash('Cannot send payment to yourself', 'error')
            return render_template('send_payment.html', user=user)
        
        # Verify PIN
        if not user.check_payment_pin(payment_pin):
            flash('Invalid payment PIN', 'error')
            return render_template('send_payment.html', user=user)
        
        # Verify recipient exists
        recipient = User.query.filter_by(payment_id=recipient_id).first()
        if not recipient:
            flash('Recipient not found', 'error')
            return render_template('send_payment.html', user=user)
        
        # Create transaction
        transaction = create_transaction(user.payment_id, recipient_id, amount)
        
        # Update balances
        user.balance -= amount
        recipient.balance += amount
        db.session.commit()
        
        # Process transactions (in a real application, this would be done by a background task)
        process_transactions()
        
        flash('Payment sent successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('send_payment.html', user=user)

@app.route('/transactions')
@login_required
def transactions():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # Get paginated transactions
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    sent_query = Transaction.query.filter_by(sender_id=user.payment_id)
    received_query = Transaction.query.filter_by(recipient_id=user.payment_id)
    
    # Combine queries for all transactions related to the user
    all_transactions = sent_query.union(received_query).order_by(Transaction.timestamp.desc())
    
    transactions = all_transactions.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('transactions.html', user=user, transactions=transactions)

@app.route('/generate_report')
@login_required
def generate_report():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # Get date range from request
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        else:
            # Default to 30 days ago
            start_date = datetime.utcnow() - timedelta(days=30)
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        else:
            # Default to today
            end_date = datetime.utcnow()
    except ValueError:
        flash('Invalid date format', 'error')
        return redirect(url_for('transactions'))
    
    # Get transactions for the date range
    sent_transactions = Transaction.query.filter(
        Transaction.sender_id == user.payment_id,
        Transaction.timestamp >= start_date,
        Transaction.timestamp <= end_date
    ).all()
    
    received_transactions = Transaction.query.filter(
        Transaction.recipient_id == user.payment_id,
        Transaction.timestamp >= start_date,
        Transaction.timestamp <= end_date
    ).all()
    
    # Calculate totals
    total_sent = sum(tx.amount for tx in sent_transactions)
    total_received = sum(tx.amount for tx in received_transactions)
    net_change = total_received - total_sent
    
    return render_template(
        'report.html',
        user=user,
        sent_transactions=sent_transactions,
        received_transactions=received_transactions,
        total_sent=total_sent,
        total_received=total_received,
        net_change=net_change,
        start_date=start_date,
        end_date=end_date
    )

@app.route('/notifications')
@login_required
def notifications():
    user_id = session.get('user_id')
    
    # Get paginated notifications
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    notifications = Notification.query.filter_by(user_id=user_id).order_by(
        Notification.is_read,
        Notification.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # Mark notifications as read
    for notification in notifications.items:
        if not notification.is_read:
            notification.is_read = True
    
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

# -------------------------
# Routes - API Endpoints
# -------------------------

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
 
def api_register():
    data = request.get_json()
    
    email = data.get('email')
    password = data.get('password')
    payment_pin = data.get('payment_pin')
    
    # Validate inputs
    if not all([email, password, payment_pin]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if not validate_password(password):
        return jsonify({'error': 'Password must be at least 8 characters and contain both letters and numbers'}), 400
    
    if not validate_pin(payment_pin):
        return jsonify({'error': 'PIN must be 6 digits'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400
    
    # Create new user
    user = User(email=email)
    user.set_password(password)
    user.set_payment_pin(payment_pin)
    user.generate_payment_id()
    user.balance = 100000.0  # Explicitly set the balance to 100,000
    db.session.add(user)
    db.session.commit()
    
    
    
    return jsonify({
        'message': 'Registration successful! Please check your email to verify your account.',
        'payment_id': user.payment_id
    }), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
 
def api_login():
    data = request.get_json()
    
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if not user.is_verified:
        return jsonify({'error': 'Please verify your email before logging in'}), 403
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Generate token
    token = generate_token(user.id)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'email': user.email,
            'payment_id': user.payment_id,
            'balance': user.balance
        }
    }), 200

@app.route('/api/user', methods=['GET'])
@token_required
def api_get_user(current_user):
    return jsonify({
        'email': current_user.email,
        'payment_id': current_user.payment_id,
        'balance': current_user.balance,
        'created_at': current_user.created_at.isoformat(),
        'last_login': current_user.last_login.isoformat() if current_user.last_login else None
    }), 200

@app.route('/api/send_payment', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def api_send_payment(current_user):
    data = request.get_json()
    
    recipient_id = data.get('recipient_id')
    amount = data.get('amount')
    payment_pin = data.get('payment_pin')
    
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400
    
    # Validate inputs
    if not all([recipient_id, amount, payment_pin]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if amount <= 0:
        return jsonify({'error': 'Amount must be greater than zero'}), 400
    
    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400
    
    if recipient_id == current_user.payment_id:
        return jsonify({'error': 'Cannot send payment to yourself'}), 400
    
    # Verify PIN
    if not current_user.check_payment_pin(payment_pin):
        return jsonify({'error': 'Invalid payment PIN'}), 401
    
    # Verify recipient exists
    recipient = User.query.filter_by(payment_id=recipient_id).first()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # Create transaction
    transaction = create_transaction(current_user.payment_id, recipient_id, amount)
    
    # Update balances
    current_user.balance -= amount
    recipient.balance += amount
    db.session.commit()
    
    # Process transactions (in a real application, this would be done by a background task)
    process_transactions()
    
    return jsonify({
        'message': 'Payment sent successfully',
        'transaction_id': transaction.transaction_hash,
        'new_balance': current_user.balance
    }), 200

@app.route('/api/transactions', methods=['GET'])
@token_required
def api_get_transactions(current_user):
    # Get optional filter parameters
    type_filter = request.args.get('type')  # 'sent', 'received', or 'all'
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        else:
            # Default to 30 days ago
            start_date = datetime.utcnow() - timedelta(days=30)
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        else:
            # Default to today
            end_date = datetime.utcnow()
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    # Build query based on filters
    if type_filter == 'sent':
        transactions = Transaction.query.filter(
            Transaction.sender_id == current_user.payment_id,
            Transaction.timestamp >= start_date,
            Transaction.timestamp <= end_date
        ).order_by(Transaction.timestamp.desc()).all()
    elif type_filter == 'received':
        transactions = Transaction.query.filter(
            Transaction.recipient_id == current_user.payment_id,
            Transaction.timestamp >= start_date,
            Transaction.timestamp <= end_date
        ).order_by(Transaction.timestamp.desc()).all()
    else:  # 'all' or no filter
        sent_query = Transaction.query.filter(
            Transaction.sender_id == current_user.payment_id,
            Transaction.timestamp >= start_date,
            Transaction.timestamp <= end_date
        )
        received_query = Transaction.query.filter(
            Transaction.recipient_id == current_user.payment_id,
            Transaction.timestamp >= start_date,
            Transaction.timestamp <= end_date
        )
        transactions = sent_query.union(received_query).order_by(Transaction.timestamp.desc()).all()
    
    # Format transactions for response
    transactions_data = []
    for tx in transactions:
        tx_data = {
            'transaction_id': tx.transaction_hash,
            'sender_id': tx.sender_id,
            'recipient_id': tx.recipient_id,
            'amount': tx.amount,
            'timestamp': tx.timestamp.isoformat(),
            'status': tx.status,
            'block_number': tx.block_number
        }
        transactions_data.append(tx_data)
    
    return jsonify({
        'transactions': transactions_data,
        'total_count': len(transactions_data)
    }), 200

@app.route('/api/notifications', methods=['GET'])
@token_required
def api_get_notifications(current_user):
    # Get unread parameter
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    # Get paginated notifications
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Build query
    query = Notification.query.filter_by(user_id=current_user.id)
    if unread_only:
        query = query.filter_by(is_read=False)
    
    query = query.order_by(Notification.created_at.desc())
    notifications = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Format notifications for response
    notifications_data = []
    for notification in notifications.items:
        notification_data = {
            'id': notification.id,
            'message': notification.message,
            'is_read': notification.is_read,
            'created_at': notification.created_at.isoformat()
        }
        notifications_data.append(notification_data)
        
        # Mark as read if not already read
        if not notification.is_read:
            notification.is_read = True
    
    db.session.commit()
    
    return jsonify({
        'notifications': notifications_data,
        'total': notifications.total,
        'pages': notifications.pages,
        'current_page': notifications.page
    }), 200

@app.route('/api/notifications/mark_read', methods=['POST'])
@token_required
def api_mark_notifications_read(current_user):
    data = request.get_json()
    notification_ids = data.get('notification_ids', [])
    
    if not notification_ids:
        # Mark all notifications as read if no IDs provided
        notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
        for notification in notifications:
            notification.is_read = True
        
        db.session.commit()
        return jsonify({'message': f'Marked {len(notifications)} notifications as read'}), 200
    
    # Mark specific notifications as read
    updated_count = 0
    for notification_id in notification_ids:
        notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
        if notification and not notification.is_read:
            notification.is_read = True
            updated_count += 1
    
    db.session.commit()
    
    return jsonify({'message': f'Marked {updated_count} notifications as read'}), 200

@app.route('/api/notifications/delete_all', methods=['DELETE'])
@token_required
def api_delete_all_notifications(current_user):
    """Delete all notifications for the current user"""
    user_id = current_user.id
    
    try:
        # Delete all notifications for the user
        Notification.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'All notifications deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/blockchain/status', methods=['GET'])
@token_required
def api_blockchain_status(current_user):
    blockchain = Blockchain()
    latest_block = blockchain.get_latest_block()
    
    # Get the number of transactions in the latest block
    transactions = json.loads(latest_block.transactions) if latest_block else []
    
    # Get some blockchain statistics
    block_count = Block.query.count()
    transaction_count = Transaction.query.count()
    completed_transaction_count = Transaction.query.filter_by(status="completed").count()
    pending_transaction_count = Transaction.query.filter_by(status="pending").count()
    
    # Check blockchain integrity
    is_valid = blockchain.verify_chain()
    
    return jsonify({
        'latest_block': {
            'block_number': latest_block.block_number,
            'timestamp': latest_block.timestamp.isoformat(),
            'transaction_count': len(transactions),
            'hash': latest_block.hash,
            'nonce': latest_block.nonce,
            'difficulty': latest_block.difficulty
        },
        'total_blocks': block_count,
        'total_transactions': transaction_count,
        'completed_transactions': completed_transaction_count,
        'pending_transactions': pending_transaction_count,
        'blockchain_valid': is_valid
    }), 200

@app.route('/api/blockchain/blocks', methods=['GET'])
def api_blockchain_blocks():
    # Get paginated blocks
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    blocks = Block.query.order_by(Block.block_number.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    # Format blocks for response
    blocks_data = []
    for block in blocks.items:
        transactions = json.loads(block.transactions)
        block_data = {
            'block_number': block.block_number,
            'timestamp': block.timestamp.isoformat(),
            'transaction_count': len(transactions),
            'hash': block.hash,
            'previous_hash': block.previous_hash,
            'nonce': block.nonce,
            'difficulty': block.difficulty,
            'is_valid': block.is_valid
        }
        blocks_data.append(block_data)
    
    return jsonify({
        'blocks': blocks_data,
        'total': blocks.total,
        'pages': blocks.pages,
        'current_page': blocks.page
    }), 200

@app.route('/api/blockchain/block/<int:block_number>', methods=['GET'])
def api_blockchain_block(block_number):
    block = Block.query.filter_by(block_number=block_number).first()
    
    if not block:
        return jsonify({'error': 'Block not found'}), 404
    
    # Get transactions in this block
    transactions = json.loads(block.transactions)
    
    # Format block data
    block_data = {
        'block_number': block.block_number,
        'timestamp': block.timestamp.isoformat(),
        'transactions': transactions,
        'transaction_count': len(transactions),
        'hash': block.hash,
        'previous_hash': block.previous_hash,
        'nonce': block.nonce,
        'difficulty': block.difficulty,
        'is_valid': block.is_valid
    }
    
    return jsonify(block_data), 200

@app.route('/api/transaction/<transaction_hash>', methods=['GET'])
def api_transaction(transaction_hash):
    transaction = Transaction.query.filter_by(transaction_hash=transaction_hash).first()
    
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    # Format transaction data
    transaction_data = {
        'transaction_hash': transaction.transaction_hash,
        'sender_id': transaction.sender_id,
        'recipient_id': transaction.recipient_id,
        'amount': transaction.amount,
        'timestamp': transaction.timestamp.isoformat(),
        'status': transaction.status,
        'block_number': transaction.block_number
    }
    
    return jsonify(transaction_data), 200

@app.route('/api/user/change_password', methods=['POST'])
@token_required
def api_change_password(current_user):
    data = request.get_json()
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if not current_user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    
    if not validate_password(new_password):
        return jsonify({'error': 'Password must be at least 8 characters and contain both letters and numbers'}), 400
    
    # Update password
    current_user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/api/user/change_pin', methods=['POST'])
@token_required
def api_change_pin(current_user):
    data = request.get_json()
    
    current_pin = data.get('current_pin')
    new_pin = data.get('new_pin')
    confirm_pin = data.get('confirm_pin')
    password = data.get('password')  # Additional security for PIN change
    
    if not all([current_pin, new_pin, confirm_pin, password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if not current_user.check_password(password):
        return jsonify({'error': 'Password is incorrect'}), 401
    
    if not current_user.check_payment_pin(current_pin):
        return jsonify({'error': 'Current PIN is incorrect'}), 401
    
    if new_pin != confirm_pin:
        return jsonify({'error': 'New PINs do not match'}), 400
    
    if not validate_pin(new_pin):
        return jsonify({'error': 'PIN must be 6 digits'}), 400
    
    # Update PIN
    current_user.set_payment_pin(new_pin)
    db.session.commit()
    
    return jsonify({'message': 'PIN updated successfully'}), 200


# -------------------------
# Additional Web Routes
# -------------------------

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('reset_password.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        if not validate_password(password):
            flash('Password must be at least 8 characters and contain both letters and numbers', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user.set_password(password)
        user.verification_token = None
        db.session.commit()
        
        flash('Your password has been reset successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not all([current_password, new_password, confirm_password]):
                flash('All password fields are required', 'error')
                return redirect(url_for('profile'))
            
            if not user.check_password(current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('profile'))
            
            if not validate_password(new_password):
                flash('Password must be at least 8 characters and contain both letters and numbers', 'error')
                return redirect(url_for('profile'))
            
            # Update password
            user.set_password(new_password)
            db.session.commit()
            
            flash('Password updated successfully', 'success')
            return redirect(url_for('profile'))
        
        elif action == 'change_pin':
            current_pin = request.form.get('current_pin')
            new_pin = request.form.get('new_pin')
            confirm_pin = request.form.get('confirm_pin')
            
            if not all([current_pin, new_pin, confirm_pin]):
                flash('All PIN fields are required', 'error')
                return redirect(url_for('profile'))
            
            if not user.check_payment_pin(current_pin):
                flash('Current PIN is incorrect', 'error')
                return redirect(url_for('profile'))
            
            if new_pin != confirm_pin:
                flash('New PINs do not match', 'error')
                return redirect(url_for('profile'))
            
            if not validate_pin(new_pin):
                flash('PIN must be 6 digits', 'error')
                return redirect(url_for('profile'))
            
            # Update PIN
            user.set_payment_pin(new_pin)
            db.session.commit()
            
            flash('PIN updated successfully', 'success')
            return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

@app.route('/blockchain')
@login_required
def blockchain_transactions():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # Get all user transactions
    sent_transactions = Transaction.query.filter_by(sender_id=user.payment_id).order_by(Transaction.timestamp.desc()).all()
    received_transactions = Transaction.query.filter_by(recipient_id=user.payment_id).order_by(Transaction.timestamp.desc()).all()
    
    # Combine and format transactions
    transactions = []
    for tx in sent_transactions + received_transactions:
        # Determine transaction type
        if tx.sender_id == user.payment_id:
            tx_type = 'sent'
            other_party = tx.recipient_id
        else:
            tx_type = 'received'
            other_party = tx.sender_id
        
        # Get block information if transaction is completed
        block_info = None
                # In the route function, make sure block_number is an integer
        if tx.block_number is not None:
            block_number = int(tx.block_number)  # Ensure it's an integer
            block = Block.query.filter_by(block_number=block_number).first()
            if block:
                block_info = {
                    'block_number': block.block_number,
                    'hash': block.hash,
                    'timestamp': block.timestamp
                }
        
        transactions.append({
            'transaction_hash': tx.transaction_hash,
            'type': tx_type,
            'amount': tx.amount,
            'other_party': other_party,
            'timestamp': tx.timestamp,
            'status': tx.status,
            'block_info': block_info
        })
    
    # Sort by timestamp, newest first
    transactions.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get blockchain status
    blockchain = Blockchain()
    is_valid = blockchain.verify_chain()
    block_count = Block.query.count()
    
    return render_template(
        'blockchain.html',
        user=user,
        transactions=transactions,
        blockchain_valid=is_valid,
        block_count=block_count
    )

@app.route('/block/<int:block_number>')
@login_required
def view_block(block_number):
    block = Block.query.filter_by(block_number=block_number).first()
    
    if not block:
        flash('Block not found', 'error')
        return redirect(url_for('blockchain_explorer'))
    
    # Get transactions in this block
    transactions_data = json.loads(block.transactions)
    
    # Get transaction details from database
    transactions = []
    for tx_data in transactions_data:
        tx = Transaction.query.filter_by(transaction_hash=tx_data['transaction_hash']).first()
        if tx:
            transactions.append(tx)
    
    return render_template('block_details.html', block=block, transactions=transactions)

@app.route('/validate_blockchain')
@login_required
def validate_blockchain():
    blockchain = Blockchain()
    is_valid = blockchain.verify_chain()
    
    if is_valid:
        flash('Blockchain validation successful! The blockchain is intact and valid.', 'success')
    else:
        flash('Blockchain validation failed! The blockchain has been tampered with.', 'error')
    
    return redirect(url_for('blockchain_explorer'))

# -------------------------
# Error Handlers
# -------------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# -------------------------
# API Documentation
# -------------------------

@app.route('/api/docs')
def api_docs():
    return render_template('api_docs.html')

# -------------------------
# Application Initialization
# -------------------------

def init_app():
    """Initialize application with database and blockchain"""
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Initialize blockchain
        blockchain = Blockchain()
        
        # Check if there are blocks in the blockchain
        if Block.query.count() == 0:
            print("Creating genesis block...")
            blockchain.create_genesis_block()
        
        # Verify blockchain integrity
        if not blockchain.verify_chain():
            print("WARNING: Blockchain integrity check failed!")
        else:
            print("Blockchain integrity verified.")

# Run the application
if __name__ == '__main__':
    init_app()
    app.run(debug=True,host='0.0.0.0')  # Set debug=False in production