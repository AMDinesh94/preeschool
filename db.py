import sqlite3
from werkzeug.security import generate_password_hash

# Sample Data
users = [
    ('teacher1', generate_password_hash('teacherpassword1'), 'teacher'),
    ('teacher2', generate_password_hash('teacherpassword2'), 'teacher'),
    ('student1', generate_password_hash('studentpassword1'), 'student'),
    ('student2', generate_password_hash('studentpassword2'), 'student')
]

# Insert data into the users table
def insert_sample_data():
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    # Insert multiple sample users
    cursor.executemany('''
        INSERT INTO users (username, password, role) VALUES (?, ?, ?)
    ''', users)

    conn.commit()
    conn.close()
    print("Sample data inserted successfully.")

# Run the function to insert data
insert_sample_data()
