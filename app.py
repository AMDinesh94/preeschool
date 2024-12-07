from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def query_db(query, args=(), one=False):
    conn = sqlite3.connect('students.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('home.html') 

@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM users WHERE username = ? AND role = ?', [username, 'student'], one=True)

        if user:
            if check_password_hash(user['password'], password):
                session['user'] = user['username']
                session['role'] = user['role']

                return redirect(url_for('student_dashboard'))
            else:
                flash('Incorrect password. Please try again.', category="login")
        else:
            flash('User not found. Please check your username.', category="login")

    return render_template('login/student_login.html')

@app.route('/teacher_login', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM users WHERE username = ? AND role = ?', [username, 'teacher'], one=True)

        if user:
            if check_password_hash(user['password'], password):
                session['user'] = user['username']
                session['role'] = user['role']
                #flash('Login successful!', 'success')
                return redirect(url_for('teacher_dashboard'))
            else:
                flash('Incorrect password. Please try again.', 'danger', category="login")
        else:
            flash('User not found. Please check your username.', 'danger', category="login")

    return render_template('login/teacher_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        fullname = request.form['fullname']
        email = request.form['email']
        parentcontactno = request.form['contactno']
        parentname = request.form['parentname']
        address = request.form['address']

        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('students.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password, role, fullname, address, email, parentname, parentcontactno) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
                       (username, hashed_password, role, fullname, address, email, parentname, parentcontactno))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/teacher_dashboard')
def teacher_dashboard():
    if 'user' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    return render_template('teacher_dashboard.html', username=session['user'])

@app.route('/massage')
def massage():
    if 'user' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    messages = query_db('SELECT * FROM messages WHERE sender_username = ? ORDER BY date_sent DESC', 
                        [session['user']])
    
    return render_template('massage.html', username=session['user'], messages=messages)


@app.route('/student_dashboard')
def student_dashboard():
    if 'user' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    return render_template('student_dashboard.html', username=session['user'])

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    session.pop('role', None) 
#    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/userslist')
def userslist():
    if 'user' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    users = query_db('SELECT * FROM users')

    return render_template('users_list.html', users=users, username=session['user'])

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = query_db('SELECT * FROM users WHERE username = ?', [session['user']], one=True)

    if not user:
        return redirect(url_for('login'))

    return render_template('profile.html', user=user, username=session['user'])

def allowed_file(filename):
    """Check if the file is an allowed image type."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/save_profile', methods=['POST'])
def save_profile():
    if 'user' not in session:
        return redirect(url_for('login'))


    user = query_db('SELECT * FROM users WHERE username = ?', [session['user']], one=True)
    
    # Get the form data
    fullname = request.form['fullname']
    user_name = request.form['user_name']
    user_email = request.form['user_email']
    user_role = request.form['user_role']
    address = request.form['address']
    parentname = request.form['parentname']
    contactno = request.form['contactno']
    password = request.form['user_password']

    # Handle file upload if a new profile image is selected
    file = request.files.get('profile_image_upload')
    profile_image_filename = user['profile_image'] 

    if file and allowed_file(file.filename):
        # Secure the filename and save it
        profile_image_filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], profile_image_filename))

    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE users
        SET username = ?, fullname = ?, email = ?, role = ?, address = ?, parentname = ?, parentcontactno = ?, profile_image = ?
        WHERE username = ?
    ''', (user_name, fullname, user_email, user_role, address, parentname, contactno, profile_image_filename, session['user']))
    
    conn.commit()
    conn.close()

    flash('Profile updated successfully!', category="profile")
    return redirect(url_for('profile'))

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    message_content = request.form['message']
    sender = session['user']
    
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    cursor.execute('INSERT INTO messages (sender_username, message) VALUES (?, ?)', 
                   (sender, message_content))

    message_id = cursor.lastrowid

    students = query_db('SELECT * FROM users WHERE role = ?', ['student'])
    for student in students:
        cursor.execute('INSERT INTO student_messages (student_username, message_id) VALUES (?, ?)', 
                       (student['username'], message_id))
    
    conn.commit()
    conn.close()
    
    flash('Message sent to all students!', category="messages")
    return redirect(url_for('massage'))

@app.route('/student_messages')
def student_messages():
    if 'user' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    student_username = session['user']
    
    student_message_ids = query_db('SELECT message_id FROM student_messages WHERE student_username = ?', 
                                   [student_username])

    messages = []
    for message_id in student_message_ids:
        message = query_db('SELECT * FROM messages WHERE id = ?', [message_id['message_id']], one=True)
        if message:
            messages.append(message)

    messages.reverse()
    
    return render_template('student_messages.html', messages=messages, username=session['user'])

@app.route('/update_user', methods=['POST'])
def update_user():
    if 'user' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    user_id = request.form['id']
    fullname = request.form['fullname']
    email = request.form['email']
    role = request.form['role']
    address = request.form['address']
    parentname = request.form['parentname']
    parentcontactno = request.form['parentcontactno']
    
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE users
        SET fullname = ?, email = ?, role = ?, address = ?, parentname = ?, parentcontactno = ?
        WHERE id = ?
    ''', (fullname, email, role, address, parentname, parentcontactno, user_id))
    
    conn.commit()
    conn.close()
    
    flash('User information updated successfully!', category="userlist")
    return redirect(url_for('userslist'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'user' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    user_id = request.form['id']
    
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!', category="userlist")
    return redirect(url_for('userslist'))


@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)
