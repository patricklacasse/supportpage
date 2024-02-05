from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, user_logged_in, user_logged_out
from flask_bcrypt import Bcrypt
from flask_bcrypt import check_password_hash
from flask_socketio import SocketIO, emit
from flask_wtf.file import FileField, FileRequired
from werkzeug.utils import secure_filename
from flask_bcrypt import generate_password_hash
import os
from flask import render_template
from sqlalchemy import or_
from flask_wtf.csrf import generate_csrf
from dotenv import load_dotenv
from flask_login import current_user
from flask_socketio import emit
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import TextAreaField, SubmitField
from flask_session import Session
from datetime import timedelta
from flask import session
from io import StringIO
from io import BytesIO
import networkx as nx
from xml.etree import ElementTree as ET
import subprocess
from sqlalchemy.orm.exc import NoResultFound

app = Flask(__name__)
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')


app.config['UPLOAD_FOLDER'] = 'static'
app.static_folder = 'static'
app.config['SESSION_TYPE'] = 'filesystem'  
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) 
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)



class VisitorProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    cookies = db.Column(db.Text, nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    plugins_extensions = db.Column(db.String(255), nullable=True)
    language_settings = db.Column(db.String(255), nullable=True)
    referrer = db.Column(db.String(255), nullable=True)
    canvas_fingerprint = db.Column(db.String(255), nullable=True)

class CaseFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(20), unique=True, nullable=False)
    case_name = db.Column(db.String(50), nullable=False)
    date_opened = db.Column(db.Date, nullable=False)
    notes = db.relationship('CaseNote', backref='case_file', lazy=True)

class CaseNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_text = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    case_file_id = db.Column(db.Integer, db.ForeignKey('case_file.id'), nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Staff(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    department = db.Column(db.String(50), nullable=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    postal_code = db.Column(db.String(10), nullable=False)
    last_ip = db.Column(db.String(15))
    country = db.Column(db.String(50))
    photo = db.Column(db.String(255))

class NmapScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text, nullable=False)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tickets', lazy=True)
    chat_messages = db.Column(db.Text, default='', nullable=True)
    user_email = db.Column(db.String(120), nullable=True)  # Add this line

class AddNoteForm(FlaskForm):
    note_text = TextAreaField('Note', validators=[FileRequired()])
    file = FileField('Attachment', validators=[FileAllowed(['pdf', 'png', 'jpg', 'jpeg', 'gif'])])
    submit = SubmitField('Add Note')

@app.before_request
def before_request():
    
    user_id = session.get('user_id')

    if user_id:
        try:
            
            existing_user = db.session.get(VisitorProfile, user_id)
        except NoResultFound:
            existing_user = None
    else:
        
        real_ip = request.headers.get('CF-Connecting-IP')

        
        visitor_profile = VisitorProfile(
            ip_address=real_ip,
            user_agent=request.user_agent.string,
            cookies=str(request.cookies),
            device_info=request.headers.get('User-Agent'),
            plugins_extensions=request.headers.get('Sec-CH-UA-Extensions'),
            language_settings=request.headers.get('Accept-Language'),
            referrer=request.headers.get('Referer'),
            canvas_fingerprint=request.headers.get('Sec-CH-2')
        )

        try:
            db.session.add(visitor_profile)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error storing visitor profile: {str(e)}")

       
        session['user_id'] = visitor_profile.id


def get_profile_by_id(profile_id):
    return Profile.query.get(profile_id)

def staff_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Is authenticated: {current_user.is_authenticated}")
        print(f"Username: {current_user.username}")
        
        if not current_user.is_authenticated or not isinstance(current_user, Staff):
            return redirect(url_for('staff_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    if current_user.is_authenticated:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=5)
    else:
        session.permanent = False
        app.permanent_session_lifetime = timedelta(days=1)

@user_logged_in.connect_via(app)
def on_user_logged_in(sender, user):
    session['user_id'] = user.get_id()

@user_logged_out.connect_via(app)
def on_user_logged_out(sender, user):
    session.pop('user_id', None)

@login_manager.user_loader
def load_user(user_id):
    
    staff = db.session.query(Staff).get(int(user_id))
    if staff:
        return staff
    
    
    user = User.query.get(int(user_id))
    return user

@app.route('/perform_nmap_scan', methods=['POST'])
def perform_nmap_scan():
    target = request.form.get('target')

    
    nmap_command = ['nmap', '-O', '-traceroute', target]  # Example: Ping scan (-sP)

    try:
        
        nmap_result_bytes = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT)
        nmap_result = nmap_result_bytes.decode('utf-8')
        
        
        scan_result = NmapScanResult(target=target, result=nmap_result)
        db.session.add(scan_result)
        db.session.commit()

        
        return jsonify({'result': nmap_result})
    except subprocess.CalledProcessError as e:
       
        error_message = f"Error running Nmap command: {e.output.decode('utf-8')}"
        return jsonify({'error': error_message})

def process_nmap_results_from_string(xml_string):
    G = nx.Graph()

    
    root = ET.fromstring(xml_string)

    router_ip = None

    for host_elem in root.findall(".//host/status[@state='up']/.."):
        ip_elem = host_elem.find(".//address[@addrtype='ipv4']")
        if ip_elem is not None:
            ip_address = ip_elem.get("addr")
            G.add_node(ip_address)

            os_elem = host_elem.find(".//os/osmatch")
            if os_elem is not None and "router" in os_elem.get("name", "").lower():
                router_ip = ip_address

    if router_ip:
        for host_elem in root.findall(".//host/status[@state='up']/.."):
            ip_elem = host_elem.find(".//address[@addrtype='ipv4']")
            if ip_elem is not None:
                ip_address = ip_elem.get("addr")
                if ip_address != router_ip:
                    G.add_edge(router_ip, ip_address)

    return G

@app.route('/view_network_graph', methods=['GET', 'POST'])
def view_network_graph():
    if request.method == 'POST':
        nmap_results = request.form.get('nmap_results')
        try:
            graph = process_nmap_results_from_string(nmap_results)
            
            graph_data = {
                'nodes': [{'id': node} for node in graph.nodes],
                'links': [{'source': edge[0], 'target': edge[1]} for edge in graph.edges],
            }
            return render_template('view_network_graph.html', network_graph=graph_data)
        except Exception as e:
            error_message = f"Error processing Nmap results: {str(e)}"
            return render_template('view_network_graph.html', error_message=error_message)

    return render_template('view_network_graph.html', network_graph=None, error_message=None)



@app.route('/add_message/<int:ticket_id>', methods=['POST'])
@login_required  
def add_message(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == 'POST':
        new_message = request.form.get('new_message')
        if new_message:
              
            ticket.chat_messages = f"{ticket.chat_messages}\n<p>{new_message}</p>"
            db.session.commit()

    return redirect(url_for('view_ticket', ticket_id=ticket.id))


@app.route('/staff/view_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def staff_view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == 'POST':
        new_message = request.form.get('new_message')
        if new_message:
            
            ticket.chat_messages = f"{ticket.chat_messages}\n<p>{new_message}</p>"
            db.session.commit()

    return render_template('staff_view_ticket.html', ticket=ticket)



@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    if request.method == 'POST':
        name = request.form.get('name')
        last_name = request.form.get('last_name')
        address = request.form.get('address')
        phone_number = request.form.get('phone_number')
        postal_code = request.form.get('postal_code')
        last_ip = request.form.get('last_ip')
        country = request.form.get('country')

        
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo.filename != '':
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                filename = None
        else:
            filename = None

        new_profile = Profile(
            name=name,
            last_name=last_name,
            address=address,
            phone_number=phone_number,
            postal_code=postal_code,
            last_ip=last_ip,
            country=country,
            photo=filename
        )
        db.session.add(new_profile)
        db.session.commit()

        flash('Profile created successfully!', 'success')
        return redirect(url_for('staff_dashboard'))

    return render_template('create_profile.html')


@app.route('/view_profiles', methods=['GET', 'POST'])
@login_required
def view_profiles():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        profiles = []

        if search_query:
           
            profiles = Profile.query.filter(or_(
                Profile.name.ilike(f"%{search_query}%"),
                Profile.last_name.ilike(f"%{search_query}%"),
                Profile.id == search_query
            )).all()

        return render_template('view_profiles.html', profiles=profiles, search_query=search_query)

    return render_template('view_profiles.html', profiles=[], search_query='')

@app.route('/create_case_file', methods=['GET', 'POST'])
@staff_login_required
def create_case_file():
    if request.method == 'POST':
        case_number = request.form.get('case_number')
        case_name = request.form.get('case_name')
        date_opened_str = request.form.get('date_opened')

        # Perform some basic form validation
        if not case_number or not case_name or not date_opened_str:
            flash('Please fill in all the fields.', 'error')
            return redirect(url_for('create_case_file'))

        try:
            date_opened = datetime.strptime(date_opened_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
            return redirect(url_for('create_case_file'))

       
        existing_case = CaseFile.query.filter_by(case_number=case_number).first()
        if existing_case:
            flash('Case number must be unique.', 'error')
            return redirect(url_for('create_case_file'))

       
        new_case_file = CaseFile(case_number=case_number, case_name=case_name, date_opened=date_opened)
        db.session.add(new_case_file)
        db.session.commit()

        flash('Case file created successfully!', 'success')
        return redirect(url_for('staff_dashboard'))

    return render_template('create_case_file.html')

@app.route('/add_note_to_case/<case_number>', methods=['POST'])
@login_required
def add_note_to_case(case_number):
    case_file = CaseFile.query.filter_by(case_number=case_number).first_or_404()
    form = AddNoteForm()

    if form.validate_on_submit():
        
        note_text = form.note_text.data
        attachment = form.file.data

        if attachment:
            
            filename = secure_filename(attachment.filename)
            attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        
        new_note = CaseNote(note_text=note_text, attachment_filename=filename)
        case_file.notes.append(new_note)  
        db.session.commit()

    return redirect(url_for('view_case_file', case_number=case_number))



@app.route('/view_case_file/<case_number>', methods=['GET', 'POST'])
@login_required
def view_case_file(case_number):
    case_file = CaseFile.query.filter_by(case_number=case_number).first_or_404()

    if request.method == 'POST':
        
        note_text = request.form.get('note')
        if note_text:
            new_note = CaseNote(note_text=note_text, case_file=case_file)
            db.session.add(new_note)
            db.session.commit()

    
    notes = CaseNote.query.filter_by(case_file_id=case_file.id).all()

    return render_template('view_case_file.html', case_file=case_file, notes=notes)



@app.route('/edit_case_file/<case_number>', methods=['POST'])
@login_required
def edit_case_file(case_number):
    case_file = CaseFile.query.filter_by(case_number=case_number).first()
    if case_file:
        
        case_file.edit_field = request.form.get('edit_field')
     
        new_note_text = request.form.get('note')
        if new_note_text:
            new_note = CaseNote(note_text=new_note_text, case_file=case_file)
            db.session.add(new_note)

        db.session.commit()

        flash('Changes saved successfully!', 'success')
        return redirect(url_for('view_case_file', case_number=case_number))
    else:
        flash('Case file not found.', 'danger')
        return redirect(url_for('view_case_files'))

@app.route('/view_case_files', methods=['GET', 'POST'])
@login_required
def view_case_files():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        case_files = []

        if search_query:
            
            case_files = CaseFile.query.filter(or_(
                CaseFile.case_number.ilike(f"%{search_query}%"),
                CaseFile.case_name.ilike(f"%{search_query}%")
            )).all()

        return render_template('view_case_files.html', case_files=case_files, search_query=search_query)

    return render_template('view_case_files.html', case_files=[], search_query='')

        

@app.route('/admin_panel')
@login_required
def admin_panel():
    
    if current_user.username == 'admin':
        staff_members = Staff.query.all()
        return render_template('admin_panel.html', staff_members=staff_members)

    flash('You do not have permission to access the admin panel.', 'danger')
    return redirect(url_for('menu'))


@app.route('/add_staff', methods=['GET', 'POST'])
@login_required
def add_staff():
    if current_user.username == 'admin':
        if request.method == 'POST':
            username = request.form.get('username')
            password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone_number = request.form.get('phone_number')
            department = request.form.get('department')

            new_staff = Staff(username=username, password=password,
                              first_name=first_name, last_name=last_name,
                              phone_number=phone_number, department=department)
            db.session.add(new_staff)
            db.session.commit()

            flash('Staff member added successfully!', 'success')
            return redirect(url_for('admin_panel'))

        return render_template('add_staff.html')

    flash('You do not have permission to add staff members.', 'danger')
    return redirect(url_for('menu'))

@app.route('/close_ticket/<int:ticket_id>')
@login_required
def close_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    print(f"Before closing - Ticket {ticket.id} status: {ticket.status}")

    
    ticket.status = 'Closed'
    db.session.commit()

    print(f"After closing - Ticket {ticket.id} status: {ticket.status}")

    
    socketio.emit('ticket_closed', {'ticket_id': ticket.id}, room=str(ticket.user_id))

    return redirect(url_for('staff_dashboard'))


@app.route('/delete_staff/<int:staff_id>')
@login_required
def delete_staff(staff_id):
    if current_user.username == 'admin':
        staff = Staff.query.get_or_404(staff_id)
        db.session.delete(staff)
        db.session.commit()

        flash('Staff member deleted successfully!', 'success')
        return redirect(url_for('admin_panel'))

    flash('You do not have permission to delete staff members.', 'danger')
    return redirect(url_for('menu'))


@app.route('/staff_login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Query the Staff table for the staff member
        staff = Staff.query.filter_by(username=username).first()

        if staff and check_password_hash(staff.password, password):
            print(f"Login successful! Logged in as {staff.username}")
            login_user(staff)
            flash('Login successful!', 'success')
            return redirect(url_for('staff_dashboard'))

        flash('Login failed. Please check your username and password.', 'danger')

    return render_template('staff_login.html')


def group_tickets_by_category(tickets):
    categories = {}
    for ticket in tickets:
        category = ticket.category
        if category not in categories:
            categories[category] = []
        categories[category].append(ticket)
    return categories


def get_closed_tickets():
    # Retrieve closed tickets from the database
    # For example, assuming you have a Ticket model
    closed_tickets = Ticket.query.filter_by(status='Closed').all()
    return closed_tickets


@app.route('/staff_dashboard')
@login_required
def staff_dashboard():
    
    open_tickets = Ticket.query.filter_by(status='Open').all()

    
    closed_tickets = get_closed_tickets()


    total_open_tickets = len(open_tickets)
    total_closed_tickets = len(closed_tickets)

    return render_template('staff_dashboard.html', 
                            tickets_by_category=group_tickets_by_category(open_tickets),
                            total_open_tickets=total_open_tickets,
                            total_closed_tickets=total_closed_tickets)

@socketio.on('send_file')
def handle_file(data):
    ticket_id = data['ticket_id']
    file_content = data['file_content']
    file_name = data['file_name']

    
    ticket = Ticket.query.get(ticket_id)
    file_link = f'<p><a href="{file_content}" target="_blank">{file_name}</a></p>'
    ticket.chat_messages += file_link
    db.session.commit()

    
    emit('receive_message', {'message': file_link}, room=str(ticket_id))

@socketio.on('close_ticket')
def close_ticket(data):
    ticket_id = data['ticket_id']
    print(f"Received close_ticket event for ticket ID: {ticket_id}")

    
    ticket = Ticket.query.get_or_404(ticket_id)
    ticket.status = 'Closed'
    db.session.commit()

    
    emit('ticket_closed', {'ticket_id': ticket_id}, broadcast=True)

@socketio.on('request_chat_history')
def send_chat_history(data):
    ticket_id = data['ticket_id']
    ticket = Ticket.query.get_or_404(ticket_id)
    
    
    emit('load_chat_history', {'chat_history': ticket.chat_messages})

@socketio.on('new_live_chat_request')
def handle_new_live_chat_request(data):
    staff_username = data['staff_username']
    
    
    room = staff_username
    emit('receive_live_chat_request', room=room)

@socketio.on('staff_message')
def handle_staff_message(data):
    
    staff_username = data['staff_username']
    message = data['message']

    
    room = staff_username
    emit('receive_staff_message', {'message': message}, room=room)


@socketio.on('send_message')
def handle_message(data):
    ticket_id = data['ticket_id']
    message = data['message']

    
    ticket = Ticket.query.get(ticket_id)
    ticket.chat_messages += f"<p>{message}</p>"  

    db.session.commit()

    
    emit('receive_message', {'message': message}, room=str(ticket_id))



@app.route('/view_tickets')
@login_required
def view_tickets():
    user_tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    return render_template('view_tickets.html', user_tickets=user_tickets)

@app.route('/view_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == 'POST':
        new_message = request.form.get('new_message')
        uploaded_file = request.files['file']

        if new_message:
            
            ticket.chat_messages = f"{ticket.chat_messages}\n<p>{new_message}</p>"

        if uploaded_file:
            
            filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join('your_upload_folder', filename))

            
            file_message = f"<p>Uploaded file: <a href='{url_for('static', filename=filename)}'>{filename}</a></p>"
            ticket.chat_messages = f"{ticket.chat_messages}\n{file_message}"

        db.session.commit()

    return render_template('view_ticket.html', ticket=ticket)

@app.route('/')
def home():
    return redirect(url_for('signup'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        
        hashed_password = generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('menu'))

        flash('Login failed. Please check your username and password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/live_chat')
@login_required
def live_chat():
    return render_template('live_chat.html')

# Route for menu
@app.route('/menu')
@login_required
def menu():
    if current_user.username == 'admin':
        return render_template('menu.html')
    elif hasattr(current_user, 'department'):
        
        return redirect(url_for('staff_dashboard'))
    else:
        return render_template('menu.html')

@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if request.method == 'POST':
        category = request.form.get('category')
        description = request.form.get('description')
        chat_message = request.form.get('chat_message')
        user_email = request.form.get('email')  

        
        new_ticket = Ticket(category=category, description=description, 
                            user_id=current_user.id, chat_messages=chat_message, 
                            user_email=user_email)  
        db.session.add(new_ticket)
        db.session.commit()

        flash('Ticket submitted successfully!', 'success')
        return redirect(url_for('menu'))

    categories = ['Cyber', 'Software', 'Hardware', 'General']
    return render_template('submit_ticket.html', categories=categories)


if __name__ == '__main__':
    with app.app_context():
        
        db.create_all()

    app.add_url_rule('/static/<filename>', 'uploaded_file', build_only=True)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
