from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from supabase import create_client, Client
import pandas as pd
from math import ceil
from functools import wraps
import bcrypt 
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import secrets
import re
from urllib.parse import urlparse
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load environment variables
load_dotenv()

# Generate a secure secret key (should be in environment variables)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))

# Configure session security
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS attacks
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)  # Session timeout
)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)
limiter.init_app(app)

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Security functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"

def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return text
    return bleach.clean(str(text).strip(), tags=[], strip=True)

def validate_url(url):
    """Validate URL format"""
    if not url:
        return True  # Optional field
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def log_error(error_message, error_code, endpoint, method):
    """Log errors to database and file"""
    try:
        logger.error(f"Error {error_code} at {endpoint} ({method}): {error_message}")
        supabase.table("error_logs").insert({
            "error_message": str(error_message),
            "error_code": error_code,
            "endpoint": endpoint,
            "method": method,
            "timestamp": datetime.utcnow().isoformat()
        }).execute()
    except Exception as e:
        logger.error(f"Failed to log error to database: {e}")

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('user_id'):
            session.clear()
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            if datetime.now() - datetime.fromisoformat(session['last_activity']) > timedelta(hours=24):
                session.clear()
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def company_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'developer':
            flash('Access denied. Developer privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def validate_property_ownership(f):
    """Ensure companies can only access their own properties"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') == 'developer':
            property_id = kwargs.get('prop_id') or request.form.get('id') or request.json.get('id')
            if property_id:
                try:
                    result = supabase.table("properties_tbl").select("developer_name").eq("id", property_id).execute()
                    if result.data:
                        property_owner = result.data[0]['developer_name']
                        if property_owner != session.get('username'):
                            flash('Access denied. You can only manage your own properties.', 'error')
                            return jsonify({'success': False, 'message': 'Access denied'}), 403
                    else:
                        flash('Property not found.', 'error')
                        return jsonify({'success': False, 'message': 'Property not found'}), 404
                except Exception as e:
                    logger.error(f"Error validating property ownership: {e}")
                    return jsonify({'success': False, 'message': 'Validation error'}), 500
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route('/')
def index():
    if 'logged_in' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'developer':
            return redirect(url_for('company_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        try:
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')
            
            # Validate inputs
            if not email or not password:
                flash('Email and password are required', 'error')
                return render_template('login.html')
            
            if not validate_email(email):
                flash('Invalid email format', 'error')
                return render_template('login.html')
            
            # Fetch user from Supabase
            result = supabase.table("tbl_users").select("*").eq("email", email).execute()
            user = result.data[0] if result.data else None
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Successful login
                session.permanent = True
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['last_activity'] = datetime.now().isoformat()
                
                logger.info(f"User {email} logged in successfully")
                
                # Redirect based on role
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'developer':
                    return redirect(url_for('company_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
                logger.warning(f"Failed login attempt for email: {email}")
                
        except Exception as e:
            flash('An error occurred. Please try again later.', 'error')
            logger.error(f"Login error: {e}")
            log_error(str(e), 500, '/login', 'POST')

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    logger.info(f"User {user_id} logged out")
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    try:
        # Fetch data with error handling
        result = supabase.table("properties_tbl").select("*").execute()
        if not result.data:
            flash('No properties found in database.', 'info')
            return render_template('dashboard.html', data=[], locations=[], companies=[], 
                                 bedrooms=[], unit_types=[], **{})
        
        raw_data = result.data
        data = pd.DataFrame(raw_data)

        # Sanitize dropdown data
        locations = sorted([sanitize_input(loc) for loc in data['location'].dropna().unique() if loc])
        companies = sorted([sanitize_input(comp) for comp in data['developer_name'].dropna().unique() if comp])
        bedrooms = sorted([sanitize_input(bed) for bed in data['bedrooms'].dropna().unique() if bed])
        unit_types = sorted([sanitize_input(unit) for unit in data['unit_type'].dropna().unique() if unit])

        # Pagination
        items_per_page = 50
        page = max(1, int(request.args.get('page', 1)))

        # Get and sanitize filters
        filters = {
            'location': sanitize_input(request.form.get('location') or request.args.get('location', '')),
            'bedrooms': sanitize_input(request.form.get('bedrooms') or request.args.get('bedrooms', '')),
            'rent_price': sanitize_input(request.form.get('rent_price') or request.args.get('rent_price', '')),
            'bin_bex': sanitize_input(request.form.get('bin_bex') or request.args.get('bin_bex', '')),
            'unit_type': sanitize_input(request.form.get('unit_type') or request.args.get('unit_type', ''))
        }

        # Apply filters
        if filters['location']:
            data = data[data['location'].str.contains(filters['location'], case=False, na=False)]
        if filters['bedrooms']:
            data = data[data['bedrooms'].astype(str) == filters['bedrooms']]
        if filters['rent_price']:
            data['rent_price'] = pd.to_numeric(data['rent_price'], errors='coerce')
            if filters['rent_price'] == '0-3000':
                data = data[data['rent_price'] <= 3000]
            elif filters['rent_price'] == '3000-5000':
                data = data[(data['rent_price'] > 3000) & (data['rent_price'] <= 5000)]
            elif filters['rent_price'] == '5000-10000':
                data = data[(data['rent_price'] > 5000) & (data['rent_price'] <= 10000)]
            elif filters['rent_price'] == '10000+':
                data = data[data['rent_price'] > 10000]
        if filters['bin_bex']:
            data = data[data['bin_bex'].str.lower() == filters['bin_bex'].lower()]
        if filters['unit_type']:
            data = data[data['unit_type'].str.lower() == filters['unit_type'].lower()]

        # Pagination
        total_items = len(data)
        total_pages = max(1, ceil(total_items / items_per_page))
        page = max(1, min(page, total_pages))
        start_idx = (page - 1) * items_per_page
        end_idx = start_idx + items_per_page
        paginated_data = data.iloc[start_idx:end_idx]

        return render_template(
            'dashboard.html',
            data=paginated_data.to_dict('records'),
            locations=locations,
            companies=companies,
            bedrooms=bedrooms,
            unit_types=unit_types,
            **{f'selected_{k}': v for k, v in filters.items()},
            pages=list(range(1, total_pages + 1)),
            total_pages=total_pages,
            current_page=page
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        log_error(str(e), 500, '/dashboard', request.method)
        flash('Error loading dashboard. Please try again.', 'error')
        return render_template('dashboard.html', data=[], locations=[], companies=[], 
                             bedrooms=[], unit_types=[], **{})

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        # Get all users (excluding passwords)
        users_result = supabase.table("tbl_users").select("id, username, email, role").execute()
        users = users_result.data if users_result.data else []

        # Get all properties
        props_result = supabase.table("properties_tbl").select("*").execute()
        properties = props_result.data if props_result.data else []

        # Get error logs (limit to recent 100)
        errors_result = supabase.table("error_logs").select("id, error_code, endpoint, timestamp").order("timestamp", desc=True).limit(100).execute()
        errors = errors_result.data if errors_result.data else []

        return render_template("admin_dashboard.html", users=users, properties=properties, errors=errors)

    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        log_error(str(e), 500, '/admin', 'GET')
        flash("Error loading admin dashboard.", "error")
        return render_template("admin_dashboard.html", users=[], properties=[], errors=[])

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
@limiter.limit("10 per hour")
def create_user():
    if request.method == 'POST':
        try:
            # Sanitize and validate inputs
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')
            role = sanitize_input(request.form.get('role', ''))
            
            # Validation
            if not all([username, email, password, role]):
                flash('All fields are required', 'error')
                return render_template('create_user.html')
            
            if not validate_email(email):
                flash('Invalid email format', 'error')
                return render_template('create_user.html')
            
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
                return render_template('create_user.html')
            
            if role not in ['user', 'admin', 'developer']:
                flash('Invalid role selected', 'error')
                return render_template('create_user.html')
            
            # Check if user already exists
            existing_user = supabase.table("tbl_users").select("id").eq("email", email).execute()
            if existing_user.data:
                flash('User with this email already exists', 'error')
                return render_template('create_user.html')
            
            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Create user
            response = supabase.table("tbl_users").insert({
                "username": username,
                "email": email,
                "password": hashed_password,
                "role": role
            }).execute()
            
            logger.info(f"Admin {session.get('username')} created user: {email}")
            flash("User created successfully", "success")
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            logger.error(f"Create user error: {e}")
            log_error(str(e), 500, '/admin/create_user', 'POST')
            flash('Error creating user. Please try again.', 'error')
    
    return render_template('create_user.html')

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    if request.method == 'POST':
        try:
            # Prevent admin from editing their own account to avoid lockout
            if user_id == session.get('user_id'):
                flash("You cannot edit your own account", "error")
                return redirect(url_for('admin_dashboard'))
            
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            role = sanitize_input(request.form.get('role', ''))
            
            # Validation
            if not all([username, email, role]):
                flash('All fields are required', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            if not validate_email(email):
                flash('Invalid email format', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            if role not in ['user', 'admin', 'developer']:
                flash('Invalid role selected', 'error')
                return redirect(url_for('edit_user', user_id=user_id))

            supabase.table("tbl_users").update({
                "username": username,
                "email": email,
                "role": role,
            }).eq("id", user_id).execute()

            logger.info(f"Admin {session.get('username')} updated user ID: {user_id}")
            flash("User updated successfully", "success")
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            logger.error(f"Edit user error: {e}")
            log_error(str(e), 500, f'/admin/edit_user/{user_id}', 'POST')
            flash("Error updating user", "error")

    # Get user data
    try:
        user_result = supabase.table("tbl_users").select("id, username, email, role").eq("id", user_id).execute()
        user = user_result.data[0] if user_result.data else None
        
        if not user:
            flash("User not found", "error")
            return redirect(url_for('admin_dashboard'))
            
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        flash("Error loading user data", "error")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        # Prevent admin from deleting their own account
        if user_id == session.get('user_id'):
            flash("You cannot delete your own account", "error")
            return redirect(url_for('admin_dashboard'))
        
        # Check if user exists
        user_result = supabase.table("tbl_users").select("username").eq("id", user_id).execute()
        if not user_result.data:
            flash("User not found", "error")
            return redirect(url_for('admin_dashboard'))
        
        username = user_result.data[0]['username']
        
        supabase.table("tbl_users").delete().eq("id", user_id).execute()
        
        logger.info(f"Admin {session.get('username')} deleted user: {username}")
        flash("User deleted successfully", "success")
        
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        log_error(str(e), 500, f'/admin/delete_user/{user_id}', 'POST')
        flash("Error deleting user", "error")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_property', methods=['GET', 'POST'])
@login_required
@admin_required
def add_property():
    if request.method == 'POST':
        try:
            # Sanitize and validate all inputs
            property_data = {
                "property_no": sanitize_input(request.form.get('property_no', '')),
                "building_no": sanitize_input(request.form.get('building_no', '')),
                "bedrooms": sanitize_input(request.form.get('bedrooms', '')),
                "rent_price": request.form.get('rent_price', ''),
                "bin_bex": sanitize_input(request.form.get('bin_bex', '')),
                "unit_type": sanitize_input(request.form.get('unit_type', '')),
                "unit_no": sanitize_input(request.form.get('unit_no', '')),
                "status": sanitize_input(request.form.get('status', '')),
                "developer_name": sanitize_input(request.form.get('developer_name', '')),
                "location": sanitize_input(request.form.get('location', '')),
                "Maps_link": sanitize_input(request.form.get('Maps_link', ''))
            }
            
            # Validate required fields
            required_fields = ['property_no', 'building_no', 'bedrooms', 'rent_price', 'developer_name', 'location']
            if not all(property_data[field] for field in required_fields):
                flash('All required fields must be filled', 'error')
                return render_template('add_property.html')
            
            # Validate rent price
            try:
                property_data['rent_price'] = float(property_data['rent_price'])
                if property_data['rent_price'] < 0:
                    flash('Rent price must be positive', 'error')
                    return render_template('add_property.html')
            except ValueError:
                flash('Invalid rent price', 'error')
                return render_template('add_property.html')
            
            # Validate enum fields
            if property_data['bin_bex'] not in ['Bin', 'Bex']:
                flash('Invalid Bin/Bex value', 'error')
                return render_template('add_property.html')
            
            if property_data['unit_type'] not in ['FF', 'SF', 'UF']:
                flash('Invalid unit type', 'error')
                return render_template('add_property.html')
            
            if property_data['status'] not in ['Vacant', 'Booked', 'Hold', 'Contracted']:
                flash('Invalid status', 'error')
                return render_template('add_property.html')
            
            # Validate Maps link if provided
            if property_data['Maps_link'] and not validate_url(property_data['Maps_link']):
                flash('Invalid Maps link format', 'error')
                return render_template('add_property.html')
            
            # Add timestamp
            
            supabase.table("properties_tbl").insert(property_data).execute()
            
            logger.info(f"Admin {session.get('username')} added property: {property_data['property_no']}")
            flash("Property added successfully", "success")
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            logger.error(f"Add property error: {e}")
            log_error(str(e), 500, '/admin/add_property', 'POST')
            flash("Error adding property", "error")
    
    return render_template('add_property.html')

@app.route('/admin/update_property_inline', methods=['POST'])
@login_required
@admin_required
def update_property_inline():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        property_id = data.get('id')
        if not property_id:
            return jsonify({'success': False, 'message': 'Property ID required'}), 400

        # Sanitize and validate data
        updated_data = {}
        for key, value in data.items():
            if key != 'id':
                updated_data[key] = sanitize_input(value)
        
        # Validate rent price
        if 'rent_price' in updated_data:
            try:
                updated_data['rent_price'] = float(updated_data['rent_price'])
                if updated_data['rent_price'] < 0:
                    return jsonify({'success': False, 'message': 'Rent price must be positive'}), 400
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid rent price'}), 400
        
        # Validate enum fields
        if updated_data.get('bin_bex') and updated_data['bin_bex'] not in ['Bin', 'Bex']:
            return jsonify({'success': False, 'message': 'Invalid Bin/Bex value'}), 400
        
        if updated_data.get('unit_type') and updated_data['unit_type'] not in ['FF', 'SF', 'UF']:
            return jsonify({'success': False, 'message': 'Invalid unit type'}), 400
        
        if updated_data.get('status') and updated_data['status'] not in ['Vacant', 'Booked', 'Hold', 'Contracted']:
            return jsonify({'success': False, 'message': 'Invalid status'}), 400
        
        # Validate Maps link
        if updated_data.get('Maps_link') and not validate_url(updated_data['Maps_link']):
            return jsonify({'success': False, 'message': 'Invalid Maps link format'}), 400
        
        supabase.table("properties_tbl").update(updated_data).eq("id", property_id).execute()
        
        logger.info(f"Admin {session.get('username')} updated property ID: {property_id}")
        return jsonify({'success': True, 'message': 'Property updated successfully.'}), 200
        
    except Exception as e:
        logger.error(f"Update property error: {e}")
        log_error(str(e), 500, '/admin/update_property_inline', 'POST')
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/admin/delete_property_inline/<int:property_id>', methods=['POST'])
@login_required
@admin_required
def delete_property_inline(property_id):
    try:
        # Check if property exists
        existing_property = supabase.table("properties_tbl").select("property_no").eq("id", property_id).execute()
        if not existing_property.data:
            return jsonify({'success': False, 'message': 'Property not found'}), 404
        
        property_no = existing_property.data[0]['property_no']
        
        supabase.table("properties_tbl").delete().eq("id", property_id).execute()
        
        logger.info(f"Admin {session.get('username')} deleted property: {property_no}")
        return jsonify({'success': True, 'message': 'Property deleted successfully.'}), 200
        
    except Exception as e:
        logger.error(f"Delete property error: {e}")
        log_error(str(e), 500, f'/admin/delete_property_inline/{property_id}', 'POST')
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/company_dashboard')
@login_required
@company_required
def company_dashboard():
    company_name = session.get('username')
    try:
        # Base query - only get properties for this company
        query = supabase.table("properties_tbl").select("*").eq("developer_name", company_name)

        # Get and sanitize filter values
        filters = {
            'property_no': sanitize_input(request.args.get('property_no', '')),
            'building_no': sanitize_input(request.args.get('building_no', '')),
            'location': sanitize_input(request.args.get('location', ''))
        }

        # Apply filters
        if filters['property_no']:
            query = query.ilike("property_no", f"%{filters['property_no']}%")
        if filters['building_no']:
            query = query.ilike("building_no", f"%{filters['building_no']}%")
        if filters['location']:
            query = query.ilike("location", f"%{filters['location']}%")

        props_result = query.execute()
        properties = props_result.data if props_result.data else []

        return render_template(
            "company_dashboard.html",
            properties=properties,
            company_name=company_name,
            **{f'filter_{k}': v for k, v in filters.items()}
        )
        
    except Exception as e:
        logger.error(f"Company dashboard error: {e}")
        log_error(str(e), 500, '/company_dashboard', 'GET')
        flash("Error loading company dashboard.", "error")
        return render_template("company_dashboard.html", properties=[], company_name=company_name)

@app.route('/company/add_property', methods=['GET', 'POST'])
@login_required
@company_required
def company_add_property():
    if request.method == 'POST':
        try:
            # Sanitize inputs
            property_data = {
                "property_no": sanitize_input(request.form.get('property_no', '')),
                "building_no": sanitize_input(request.form.get('building_no', '')),
                "bedrooms": sanitize_input(request.form.get('bedrooms', '')),
                "rent_price": request.form.get('rent_price', ''),
                "bin_bex": sanitize_input(request.form.get('bin_bex', '')),
                "unit_type": sanitize_input(request.form.get('unit_type', '')),
                "unit_no": sanitize_input(request.form.get('unit_no', '')),
                "status": sanitize_input(request.form.get('status', '')),
                "developer_name": session.get('username'),  # Force company name from session
                "location": sanitize_input(request.form.get('location', '')),
                "Maps_link": sanitize_input(request.form.get('Maps_link', ''))
            }
            
            # Validate required fields
            required_fields = ['property_no', 'building_no', 'bedrooms', 'rent_price', 'location']
            if not all(property_data[field] for field in required_fields):
                flash('All required fields must be filled', 'error')
                return render_template('company_add_property.html')
            
            # Validate rent price
            try:
                property_data['rent_price'] = float(property_data['rent_price'])
                if property_data['rent_price'] < 0:
                    flash('Rent price must be positive', 'error')
                    return render_template('company_add_property.html')
            except ValueError:
                flash('Invalid rent price', 'error')
                return render_template('company_add_property.html')
            
            # Validate enum fields
            if property_data['bin_bex'] not in ['Bin', 'Bex']:
                flash('Invalid Bin/Bex value', 'error')
                return render_template('company_add_property.html')
            
            if property_data['unit_type'] not in ['FF', 'SF', 'UF']:
                flash('Invalid unit type', 'error')
                return render_template('company_add_property.html')
            
            if property_data['status'] not in ['Vacant', 'Booked', 'Hold', 'Contracted']:
                flash('Invalid status', 'error')
                return render_template('company_add_property.html')
            
            # Validate Maps link
            if property_data['Maps_link'] and not validate_url(property_data['Maps_link']):
                flash('Invalid Maps link format', 'error')
                return render_template('company_add_property.html')
            
            
            supabase.table("properties_tbl").insert(property_data).execute()
            
            logger.info(f"Company {session.get('username')} added property: {property_data['property_no']}")
            flash("Property added successfully", "success")
            return redirect(url_for('company_dashboard'))
            
        except Exception as e:
            logger.error(f"Company add property error: {e}")
            log_error(str(e), 500, '/company/add_property', 'POST')
            flash("Error adding property", "error")
    
    return render_template('company_add_property.html')

@app.route('/company/upload_properties', methods=['POST'])
@login_required
@company_required
@limiter.limit("5 per hour")  # Limit bulk uploads
def upload_properties():
    if 'property_file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('company_dashboard'))
    
    file = request.files['property_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('company_dashboard'))

    try:
        # Validate file size (max 10MB)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            flash('File too large. Maximum size is 10MB.', 'error')
            return redirect(url_for('company_dashboard'))
        
        filename = sanitize_input(file.filename)
        if filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file)
        else:
            flash('Unsupported file format. Please upload CSV or Excel files only.', 'error')
            return redirect(url_for('company_dashboard'))

        # Validate required columns
        required_columns = ['property_no', 'building_no', 'bedrooms', 'rent_price', 'location']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            flash(f'Missing required columns: {", ".join(missing_columns)}', 'error')
            return redirect(url_for('company_dashboard'))

        # Sanitize data
        for col in df.columns:
            if col in ['property_no', 'building_no', 'bedrooms', 'bin_bex', 'unit_type', 'unit_no', 'status', 'location', 'Maps_link']:
                df[col] = df[col].astype(str).apply(sanitize_input)
        
        # Force developer name and add timestamps
        df['developer_name'] = session.get('username')
        
        # Validate data
        df['rent_price'] = pd.to_numeric(df['rent_price'], errors='coerce')
        df = df.dropna(subset=['rent_price'])  # Remove invalid prices
        df = df[df['rent_price'] >= 0]  # Remove negative prices
        
        # Validate enum fields
        valid_bin_bex = ['Bin', 'Bex']
        valid_unit_types = ['FF', 'SF', 'UF']
        valid_statuses = ['Vacant', 'Booked', 'Hold', 'Contracted']
        
        df = df[df['bin_bex'].isin(valid_bin_bex)]
        df = df[df['unit_type'].isin(valid_unit_types)]
        df = df[df['status'].isin(valid_statuses)]
        
        if len(df) == 0:
            flash('No valid properties found in the uploaded file.', 'error')
            return redirect(url_for('company_dashboard'))
        
        # Convert to records and upload
        properties_to_upload = df.to_dict(orient='records')
        
        # Batch insert with error handling
        supabase.table("properties_tbl").insert(properties_to_upload).execute()
        
        logger.info(f"Company {session.get('username')} uploaded {len(properties_to_upload)} properties")
        flash(f'{len(properties_to_upload)} properties uploaded successfully!', 'success')

    except Exception as e:
        logger.error(f"File upload error: {e}")
        log_error(str(e), 500, '/company/upload_properties', 'POST')
        flash(f'Error uploading file: {str(e)}', 'error')

    return redirect(url_for('company_dashboard'))

@app.route('/company/get_property/<int:prop_id>', methods=['GET'])
@login_required
@company_required
@validate_property_ownership
def get_property(prop_id):
    try:
        result = supabase.table("properties_tbl").select("*").eq("id", prop_id).eq("developer_name", session.get('username')).single().execute()
        if not result.data:
            return jsonify({"error": "Property not found"}), 404
        return jsonify(result.data)
    except Exception as e:
        logger.error(f"Get property error: {e}")
        log_error(str(e), 500, f'/company/get_property/{prop_id}', 'GET')
        return jsonify({"error": "Internal server error"}), 500

@app.route('/company/update_property', methods=['POST'])
@login_required
@company_required
@validate_property_ownership
def update_property():
    try:
        prop_id = int(request.form.get('id', 0))
        if prop_id <= 0:
            return jsonify({"success": False, "error": "Invalid property ID"}), 400
        
        # Sanitize and validate inputs
        update_data = {
            "property_no": sanitize_input(request.form.get('property_no', '')),
            "building_no": sanitize_input(request.form.get('building_no', '')),
            "bedrooms": sanitize_input(request.form.get('bedrooms', '')),
            "rent_price": request.form.get('rent_price', ''),
            "bin_bex": sanitize_input(request.form.get('bin_bex', '')),
            "unit_type": sanitize_input(request.form.get('unit_type', '')),
            "unit_no": sanitize_input(request.form.get('unit_no', '')),
            "status": sanitize_input(request.form.get('status', '')),
            "developer_name": session.get('username'),  # Force company name
            "location": sanitize_input(request.form.get('location', '')),
            "Maps_link": sanitize_input(request.form.get('Maps_link', ''))
        }
        
        # Validate required fields
        required_fields = ['property_no', 'building_no', 'bedrooms', 'rent_price', 'location']
        if not all(update_data[field] for field in required_fields):
            return jsonify({"success": False, "error": "All required fields must be filled"}), 400
        
        # Validate rent price
        try:
            update_data['rent_price'] = float(update_data['rent_price'])
            if update_data['rent_price'] < 0:
                return jsonify({"success": False, "error": "Rent price must be positive"}), 400
        except ValueError:
            return jsonify({"success": False, "error": "Invalid rent price"}), 400
        
        # Validate enum fields
        if update_data['bin_bex'] not in ['Bin', 'Bex']:
            return jsonify({"success": False, "error": "Invalid Bin/Bex value"}), 400
        
        if update_data['unit_type'] not in ['FF', 'SF', 'UF']:
            return jsonify({"success": False, "error": "Invalid unit type"}), 400
        
        if update_data['status'] not in ['Vacant', 'Booked', 'Hold', 'Contracted']:
            return jsonify({"success": False, "error": "Invalid status"}), 400
        
        # Validate Maps link
        if update_data['Maps_link'] and not validate_url(update_data['Maps_link']):
            return jsonify({"success": False, "error": "Invalid Maps link format"}), 400
        
        
        supabase.table("properties_tbl").update(update_data).eq("id", prop_id).eq("developer_name", session.get('username')).execute()
        
        logger.info(f"Company {session.get('username')} updated property ID: {prop_id}")
        return jsonify({"success": True}), 200
        
    except ValueError:
        return jsonify({"success": False, "error": "Invalid property ID"}), 400
    except Exception as e:
        logger.error(f"Update property error: {e}")
        log_error(str(e), 500, '/company/update_property', 'POST')
        return jsonify({"success": False, "error": "Internal server error"}), 500

@app.route('/company/delete_property/<int:prop_id>', methods=['DELETE'])
@login_required
@company_required
@validate_property_ownership
def delete_property(prop_id):
    try:
        # Verify property exists and belongs to company
        existing_property = supabase.table("properties_tbl").select("property_no").eq("id", prop_id).eq("developer_name", session.get('username')).execute()
        if not existing_property.data:
            return jsonify({"success": False, "error": "Property not found"}), 404
        
        property_no = existing_property.data[0]['property_no']
        
        supabase.table("properties_tbl").delete().eq("id", prop_id).eq("developer_name", session.get('username')).execute()
        
        logger.info(f"Company {session.get('username')} deleted property: {property_no}")
        return jsonify({"success": True}), 200
        
    except Exception as e:
        logger.error(f"Delete property error: {e}")
        log_error(str(e), 500, f'/company/delete_property/{prop_id}', 'DELETE')
        return jsonify({"success": False, "error": "Internal server error"}), 500

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
    )
    return response

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    try:
        log_error(str(e), 404, request.path, request.method)
    except Exception as err:
        logger.error(f"Error logging 404: {err}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    try:
        log_error(str(e), 500, request.path, request.method)
    except Exception as err:
        logger.error(f"Error logging 500: {err}")
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    try:
        log_error(str(e), 403, request.path, request.method)
    except Exception as err:
        logger.error(f"Error logging 403: {err}")
    return render_template('403.html'), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

if __name__ == '__main__':
    # Don't run in debug mode in production
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)