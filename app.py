from flask import Flask, render_template, request, redirect, url_for, flash
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
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



app = Flask(__name__)
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Create the SQLAlchemy instance and bind it to the app
app.config['UPLOAD_FOLDER'] = 'static'
app.static_folder = 'static'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)


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

@login_manager.user_loader
def load_user(user_id):
    # Try loading as Staff first
    staff = Staff.query.get(int(user_id))
    if staff:
        return staff
    
    # Then try loading as User
    user = User.query.get(int(user_id))
    return user

@app.route('/add_message/<int:ticket_id>', methods=['POST'])
@login_required  # Add this decorator if users need to be logged in
def add_message(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == 'POST':
        new_message = request.form.get('new_message')
        if new_message:
            # Append the new message to existing chat_messages  
            ticket.chat_messages = f"{ticket.chat_messages}\n<p>{new_message}</p>"
            db.session.commit()

    return redirect(url_for('view_ticket', ticket_id=ticket.id))

# Add a new route for staff to view tickets
@app.route('/staff/view_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def staff_view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == 'POST':
        new_message = request.form.get('new_message')
        if new_message:
            # Append the new message to existing chat_messages
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

        # Handle file upload
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

# Route for viewing profiles
@app.route('/view_profiles', methods=['GET', 'POST'])
@login_required
def view_profiles():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        profiles = []

        if search_query:
            # Perform a case-insensitive search based on name, last name, or profile ID
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
        date_opened = datetime.strptime(request.form.get('date_opened'), '%Y-%m-%d').date()

        # Create a new case file with the provided information
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
        # Handle adding notes to the case file
        note_text = form.note_text.data
        attachment = form.file.data

        if attachment:
            # Handle file upload and store the filename in the note
            filename = secure_filename(attachment.filename)
            attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        # Create a new note with the provided information
        new_note = CaseNote(note_text=note_text, attachment_filename=filename)
        case_file.notes.append(new_note)  # Assuming 'notes' is a relationship in CaseFile model
        db.session.commit()

    return redirect(url_for('view_case_file', case_number=case_number))



@app.route('/view_case_file/<case_number>', methods=['GET', 'POST'])
@login_required
def view_case_file(case_number):
    case_file = CaseFile.query.filter_by(case_number=case_number).first_or_404()

    if request.method == 'POST':
        # Handle adding notes to the case file
        note_text = request.form.get('note')
        if note_text:
            new_note = CaseNote(note_text=note_text, case_file=case_file)
            db.session.add(new_note)
            db.session.commit()

    # Fetch all notes associated with the case file
    notes = CaseNote.query.filter_by(case_file_id=case_file.id).all()

    return render_template('view_case_file.html', case_file=case_file, notes=notes)


# Add a route for editing a specific case file
@app.route('/edit_case_file/<case_number>', methods=['POST'])
@login_required
def edit_case_file(case_number):
    case_file = CaseFile.query.filter_by(case_number=case_number).first()
    if case_file:
        # Update the case file fields based on the form data
        case_file.edit_field = request.form.get('edit_field')
        # Update other fields as needed

        # Add the new note to the case file
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
            # Perform a case-insensitive search based on case number or case name
            case_files = CaseFile.query.filter(or_(
                CaseFile.case_number.ilike(f"%{search_query}%"),
                CaseFile.case_name.ilike(f"%{search_query}%")
            )).all()

        return render_template('view_case_files.html', case_files=case_files, search_query=search_query)

    return render_template('view_case_files.html', case_files=[], search_query='')

        
# Route for admin panel
@app.route('/admin_panel')
@login_required
def admin_panel():
    # Check if the current user has admin privileges
    if current_user.username == 'admin':
        staff_members = Staff.query.all()
        return render_template('admin_panel.html', staff_members=staff_members)

    flash('You do not have permission to access the admin panel.', 'danger')
    return redirect(url_for('menu'))

# Route for adding a new staff member
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

    # Update the ticket status to 'Closed'
    ticket.status = 'Closed'
    db.session.commit()

    # Emit a socket event to notify the client
    socketio.emit('ticket_closed', {'message': 'This ticket has been closed.'}, room=str(ticket.user_id))

    return redirect(url_for('staff_dashboard'))

# Route for deleting a staff member
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

# Route for staff login
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

# Route for staff dashboard
def get_closed_tickets():
    # Retrieve closed tickets from the database
    # For example, assuming you have a Ticket model
    closed_tickets = Ticket.query.filter_by(status='Closed').all()
    return closed_tickets

# Route to render staff_dashboard
@app.route('/staff_dashboard')
@login_required
def staff_dashboard():
    # Get open tickets for the staff_dashboard
    open_tickets = Ticket.query.filter_by(status='Open').all()

    # Get closed tickets for the staff_dashboard
    closed_tickets = get_closed_tickets()

    # Other statistics calculations
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

    # Update the chat messages for the ticket with the file link
    ticket = Ticket.query.get(ticket_id)
    file_link = f'<p><a href="{file_content}" target="_blank">{file_name}</a></p>'
    ticket.chat_messages += file_link
    db.session.commit()

    # Broadcast the file link to all clients in the room (ticket_id)
    emit('receive_message', {'message': file_link}, room=str(ticket_id))

@socketio.on('close_ticket')
def close_ticket(data):
    ticket_id = data['ticket_id']
    ticket = Ticket.query.get_or_404(ticket_id)

    # Update the ticket status to 'Closed'
    ticket.status = 'Closed'
    db.session.commit()

    # Notify the user that the ticket is closed
    emit('ticket_closed', {'message': 'This ticket has been closed.'}, room=str(ticket.user_id))

@socketio.on('request_chat_history')
def send_chat_history(data):
    ticket_id = data['ticket_id']
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Emit the existing chat history to the user
    emit('load_chat_history', {'chat_history': ticket.chat_messages})

@socketio.on('new_live_chat_request')
def handle_new_live_chat_request(data):
    staff_username = data['staff_username']
    
    # Broadcast the request to the specific staff member's room
    room = staff_username
    emit('receive_live_chat_request', room=room)

@socketio.on('staff_message')
def handle_staff_message(data):
    # Handle staff-specific messages here
    staff_username = data['staff_username']
    message = data['message']

    # Broadcast the message to all clients connected to the staff member's room
    room = staff_username
    emit('receive_staff_message', {'message': message}, room=room)

# SocketIO event handler for chat
@socketio.on('send_message')
def handle_message(data):
    ticket_id = data['ticket_id']
    message = data['message']

    # Update the chat messages for the ticket
    ticket = Ticket.query.get(ticket_id)
    ticket.chat_messages += f"<p>{message}</p>"  # You may need to format the message appropriately

    db.session.commit()

    # Broadcast the message to all clients in the room (ticket_id)
    emit('receive_message', {'message': message}, room=str(ticket_id))


# Route for viewing user's tickets
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
        if new_message:
            # Append the new message to existing chat_messages
            ticket.chat_messages = f"{ticket.chat_messages}\n<p>{new_message}</p>"
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

        # Hash the password before storing it
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
        # Staff members are allowed access only to staff_dashboard
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
        user_email = request.form.get('user_email')  # Add this line

        # Create a new ticket with the provided information
        new_ticket = Ticket(category=category, description=description, 
                            user_id=current_user.id, chat_messages=chat_message, 
                            user_email=user_email)  # Add this line
        db.session.add(new_ticket)
        db.session.commit()

        flash('Ticket submitted successfully!', 'success')
        return redirect(url_for('menu'))

    categories = ['Cyber', 'Software', 'Hardware', 'General']
    return render_template('submit_ticket.html', categories=categories)


if __name__ == '__main__':
    with app.app_context():
        # Create tables if they do not exist
        db.create_all()

    app.add_url_rule('/static/<filename>', 'uploaded_file', build_only=True)
    app.run(host='0.0.0.0', port=5000, debug=False)
