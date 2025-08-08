from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from supabase import create_client, Client
import pandas as pd
from math import ceil
from functools import wraps
import bcrypt 
from datetime import datetime
from dotenv import load_dotenv
import os


app = Flask(__name__)

app.secret_key = '123456789aaabbbccc@!@#@@@@'

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def company_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'developer':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route('/')
def index():
    # Redirect based on login status and role
    if 'logged_in' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session.get('role') == 'developer':
            return redirect(url_for('company_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Fetch user from Supabase
            result = supabase.table("tbl_users").select("*").eq("email", email).execute()
            user = result.data[0] if result.data else None
            # print("Supabase login result:", user)

            if user:
                hashed = user['password']
                if bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')):
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']

                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    elif user['role'] == 'developer':
                        return redirect(url_for('company_dashboard'))
                    else:
                        return redirect(url_for('dashboard'))
                else:
                    flash('Invalid email or password', 'error')
            else:
                flash('Invalid email or password', 'error')

        except Exception as e:
            flash('An error occurred. Please try again later.', 'error')
            print("Login error:", e)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

#user Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Fetch data
    result = supabase.table("properties_tbl").select("*").execute()
    raw_data = result.data
    data = pd.DataFrame(raw_data)

    # Dropdown list data
    locations = data['location'].dropna().unique().tolist() if 'location' in data.columns else []
    companies = data['developer_name'].dropna().unique().tolist() if 'developer_name' in data.columns else []
    bedrooms = data['bedrooms'].dropna().unique().tolist() if 'bedrooms' in data.columns else []
    unit_types = data['unit_type'].dropna().unique().tolist() if 'unit_type' in data.columns else []

    # Pagination
    items_per_page = 50  
    page = int(request.args.get('page', 1))  

    # Filters
    if request.method == 'POST':
        selected_location = request.form.get('location', '')
        selected_bedrooms = request.form.get('bedrooms', '')
        selected_rent_price = request.form.get('rent_price', '')
        selected_bin_bex = request.form.get('bin_bex', '')
        selected_unit_type = request.form.get('unit_type', '')
    else:
        selected_location = request.args.get('location', '')
        selected_bedrooms = request.args.get('bedrooms', '')
        selected_rent_price = request.args.get('rent_price', '')
        selected_bin_bex = request.args.get('bin_bex', '')
        selected_unit_type = request.args.get('unit_type', '')

    # Apply filters
    if selected_location:
        data = data[data['location'].str.contains(selected_location, case=False, na=False)]
    if selected_bedrooms:
        data = data[data['bedrooms'].astype(str) == selected_bedrooms]
    if selected_rent_price:
        data['rent_price'] = pd.to_numeric(data['rent_price'], errors='coerce')
        if selected_rent_price == '0-3000':
            data = data[data['rent_price'] <= 3000]
        elif selected_rent_price == '3000-5000':
            data = data[(data['rent_price'] > 3000) & (data['rent_price'] <= 5000)]
        elif selected_rent_price == '5000-10000':
            data = data[(data['rent_price'] > 5000) & (data['rent_price'] <= 10000)]
        elif selected_rent_price == '10000+':
            data = data[data['rent_price'] > 10000]
    if selected_bin_bex:
        data = data[data['bin_bex'].str.lower() == selected_bin_bex.lower()]
    if selected_unit_type:
        data = data[data['unit_type'].str.lower() == selected_unit_type.lower()]

    # Pagination after filtering
    total_items = len(data)
    total_pages = max(1, ceil(total_items / items_per_page))
    page = max(1, min(page, total_pages))
    start_idx = (page - 1) * items_per_page
    end_idx = start_idx + items_per_page
    paginated_data = data.iloc[start_idx:end_idx]

    pages = list(range(1, total_pages + 1))

    return render_template(
        'dashboard.html',
        data=paginated_data.to_dict('records'),
        locations=locations,
        companies=companies,
        bedrooms=bedrooms,
        unit_types=unit_types,
        selected_location=selected_location,
        selected_bedrooms=selected_bedrooms,
        selected_rent_price=selected_rent_price,
        selected_bin_bex=selected_bin_bex,
        selected_unit_type=selected_unit_type,
        pages=pages,
        total_pages=total_pages,
        current_page=page
    )



@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        # Get all users
        users_result = supabase.table("tbl_users").select("id, username, email, role").execute()
        users = users_result.data if users_result.data else []

        # Get all properties
        props_result = supabase.table("properties_tbl").select("*").execute()
        properties = props_result.data if props_result.data else []

        # Get error logs
        errors_result = supabase.table("error_logs").select("id, error_code, endpoint, timestamp").order("timestamp", desc=True).execute()
        errors = errors_result.data if errors_result.data else []

        return render_template("admin_dashboard.html", users=users, properties=properties, errors=errors)

    except Exception as e:
        flash("Error loading admin dashboard.", "error")
        print(f"Admin dashboard error: {e}")
        return render_template("admin_dashboard.html", users=[], properties=[], errors=[])

# User Management
@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            response = supabase.table("tbl_users").insert({
                "username": username,
                "email": email,
                "password": hashed_password,
                "role": role
            }).execute()
            flash("User created successfully", "success")
            return redirect(url_for('admin_dashboard'))
        
        except Exception as e:
            flash('User or email already exists', 'error')
    return render_template('create_user.html')

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']

        try:
            supabase.table("tbl_users").update({
                "username": username,
                "email": email,
                "role": role
            }).eq("id", user_id).execute()

            flash("User updated successfully", "success")
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            flash("Error updating user", "error")
            print(f"Edit user error: {e}")

    # Get user data
    user_result = supabase.table("tbl_users").select("id, username, email, role").eq("id", user_id).execute()
    user = user_result.data[0] if user_result.data else None

    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        supabase.table("tbl_users").delete().eq("id", user_id).execute()
        flash("User deleted successfully", "success")
    except Exception as e:
        flash("Error deleting user", "error")
        print(f"Delete user error: {e}")
    return redirect(url_for('admin_dashboard'))

#Property Management
@app.route('/admin/add_property', methods=['GET', 'POST'])
@login_required
@admin_required
def add_property():
    if request.method == 'POST':
        data = {
        "property_no": request.form['property_no'],
        "building_no": request.form['building_no'],
        "bedrooms": request.form['bedrooms'],
        "rent_price": request.form['rent_price'],
        "bin_bex": request.form['bin_bex'],
        "unit_type": request.form['unit_type'],  # FF / SF / UF
        "unit_no": request.form['unit_no'],
        "status": request.form['status'],
        "developer_name": request.form['developer_name'],
        "location": request.form['location'],
        "Maps_link": request.form['Maps_link']
}

        try:
            supabase.table("properties_tbl").insert(data).execute()
            flash("Property added successfully", "success")
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash("Error adding property", "error")
            print(f"Add property error: {e}")
    
    return render_template('add_property.html')



@app.route('/admin/update_property_inline', methods=['POST'])
@login_required
@admin_required
def update_property_inline():
    data = request.json  # Receive data as JSON
    property_id = data.get('id')

    updated_data = {
        "property_no": data.get('property_no'),
        "building_no": data.get('building_no'),
        "bedrooms": data.get('bedrooms'),
        "rent_price": data.get('rent_price'),
        "bin_bex": data.get('bin_bex'),
        "unit_type": data.get('unit_type'),  # FF / SF / UF
        "unit_no": data.get('unit_no'),
        "status": data.get('status'),
        "developer_name": data.get('developer_name'),
        "location": data.get('location'),
        "Maps_link": data.get('Maps_link')
    }

    try:
        supabase.table("properties_tbl").update(updated_data).eq("id", property_id).execute()
        return jsonify({'success': True, 'message': 'Property updated successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/delete_property_inline/<int:property_id>', methods=['POST'])
@login_required
@admin_required
def delete_property_inline(property_id):
    try:
        supabase.table("properties_tbl").delete().eq("id", property_id).execute()
        return jsonify({'success': True, 'message': 'Property deleted successfully.'}), 200
    except Exception as e:
        print(f"Error deleting property: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/company_dashboard')
@login_required
@company_required
def company_dashboard():
    company_name = session.get('username')
    try:
        # Fetch properties for the specific company
        props_result = supabase.table("properties_tbl").select("*").eq("developer_name", company_name).execute()
        properties = props_result.data if props_result.data else []
        return render_template("company_dashboard.html", properties=properties, company_name=company_name)
    except Exception as e:
        flash("Error loading company dashboard.", "error")
        print(f"Company dashboard error: {e}")
        return render_template("company_dashboard.html", properties=[], company_name=company_name)

@app.route('/company/add_property', methods=['GET', 'POST'])
@login_required
@company_required
def company_add_property():
    if request.method == 'POST':
        data = {
            "property_no": request.form['property_no'],
            "building_no": request.form['building_no'],
            "bedrooms": request.form['bedrooms'],
            "rent_price": request.form['rent_price'],
            "bin_bex": request.form['bin_bex'],
            "unit_type": request.form['unit_type'],
            "unit_no": request.form['unit_no'],
            "status": request.form['status'],
            "developer_name": session.get('username'),  # Automatically set developer name
            "location": request.form['location'],
            "Maps_link": request.form['Maps_link']
        }
        try:
            supabase.table("properties_tbl").insert(data).execute()
            flash("Property added successfully", "success")
            return redirect(url_for('company_dashboard'))
        except Exception as e:
            flash("Error adding property", "error")
            print(f"Add property error: {e}")
    
    return render_template('company_add_property.html')


@app.route('/company/upload_properties', methods=['POST'])
@login_required
@company_required
def upload_properties():
    if 'property_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('company_dashboard'))
    
    file = request.files['property_file']

    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('company_dashboard'))

    if file:
        try:
            filename = file.filename
            if filename.endswith('.csv'):
                df = pd.read_csv(file)
            elif filename.endswith('.xls') or filename.endswith('.xlsx'):
                df = pd.read_excel(file)
            else:
                flash('Unsupported file format. Please upload a CSV or Excel file.', 'error')
                return redirect(url_for('company_dashboard'))

            # Assuming the excel/csv has columns matching the database table
            # And we need to add the developer_name
            df['developer_name'] = session.get('username')
            
            # Convert DataFrame to list of dictionaries
            properties_to_upload = df.to_dict(orient='records')
            
            # Insert data into Supabase
            supabase.table("properties_tbl").insert(properties_to_upload).execute()
            
            flash(f'{len(properties_to_upload)} properties uploaded successfully!', 'success')

        except Exception as e:
            flash(f'An error occurred during file upload: {e}', 'error')
            print(f"File upload error: {e}")

    return redirect(url_for('company_dashboard'))

@app.errorhandler(404)
def page_not_found(e):
    try:
        supabase.table("error_logs").insert({
            "error_message": str(e),
            "error_code": 404,
            "endpoint": request.path,
            "method": request.method
        }).execute()
    except Exception as err:
        print(f"Error logging 404: {err}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    try:
        supabase.table("error_logs").insert({
            "error_message": str(e),
            "error_code": 500,
            "endpoint": request.path,
            "method": request.method
        }).execute()
    except Exception as err:
        print(f"Error logging 500: {err}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
