from flask import Flask, render_template, request, redirect, session
import numpy as np
import pickle
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Load the diabetes prediction model
with open('ml_model.pkl', 'rb') as file:
    classifier = pickle.load(file)

# SQLite database connection setup
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
# Initialize database
def init_db():
    conn = get_db_connection()

    # Create the 'users' table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            phonenumber TEXT,
            gender TEXT,
            age INTEGER
        )
    ''')

    # Create the 'admin' table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Create the 'disease' table with an additional email column
    conn.execute('''
        CREATE TABLE IF NOT EXISTS disease (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,  -- New column for storing email
            pregnancies INTEGER NOT NULL,
            glucose INTEGER NOT NULL,
            blood_pressure INTEGER NOT NULL,
            skin_thickness INTEGER NOT NULL,
            insulin INTEGER NOT NULL,
            bmi REAL NOT NULL,
            dpf REAL NOT NULL,
            age INTEGER NOT NULL,
            prediction TEXT NOT NULL
        )
    ''')

    # Check if the default admin exists
    admin_check = conn.execute('SELECT * FROM admin WHERE email = ?', ('admin@gmail.com',)).fetchone()

    # If the default admin does not exist, insert it
    if admin_check is None:
        conn.execute('''
            INSERT INTO admin (name, email, password) VALUES (?, ?, ?)
        ''', ('admin', 'admin@gmail.com', generate_password_hash('admin')))  # Hash the default admin password

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    if 'logged_in' in session and session['logged_in']:
        return render_template('home.html', home_active='active')
    else:
        return redirect('/login') 
 
@app.route('/about')
def about():
    return render_template('about.html', about_active='active')
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        email = request.form['email']
        phonenumber = request.form['phone']  # Changed to phonenumber to match database column
        gender = request.form['gender']
        age = request.form['age']

        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, email, phonenumber, gender, age) VALUES (?, ?, ?, ?, ?, ?)', 
                     (username, password, email, phonenumber, gender, age))
        conn.commit()
        conn.close()

        return redirect('/login')
    return render_template('register.html')
  
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']

        # Database query to validate user
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # Set session with user details
            session['username'] = user['username']
            session['logged_in'] = True

            # Redirect to prediction page after successful login 
            return redirect('/predict') 
        else:  
            error_message = "Invalid email or password. Please try again."
            return render_template('login.html', error_message=error_message, login_active='active')

    return render_template('login.html', login_active='active')
 
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Database query to validate admin credentials
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admin WHERE email = ?', (email,)).fetchone()
        conn.close()

        if admin and check_password_hash(admin['password'], password):
            session['admin_logged_in'] = True
            return redirect('/admin_dashboard')
        else:
            error_message = "Invalid admin credentials. Please try again."
            return render_template('admin_login.html', error_message=error_message, admin_active='active')
 
    return render_template('admin_login.html', admin_active='active')
  
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_logged_in' in session:
        return render_template('admin_dashboard.html')
    return redirect('/admin')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'username' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    if request.method == 'POST':
        username = session['username']

        # Fetch the email of the logged-in user
        conn = get_db_connection()
        user = conn.execute('SELECT email FROM users WHERE username = ?', (username,)).fetchone()
        email = user['email']
        conn.close()

        num_preg = request.form.get('Pregnancies')
        glucose_conc = request.form.get('Glucose')
        diastolic_bp = request.form.get('BloodPressure')
        thickness = request.form.get('SkinThickness')
        insulin = request.form.get('InsulinLevel')
        bmi = request.form.get('BodyMassIndex')
        dpf = request.form.get('DiabetesPedigreeFunction')
        age = request.form.get('Age')

        # Prepare data for prediction
        data = np.array([[int(num_preg), int(glucose_conc), int(diastolic_bp), int(thickness), int(insulin), float(bmi), float(dpf), int(age)]])
        prediction = classifier.predict(data)
        prediction_result = "Positive" if prediction[0] else "Negative"  # More user-friendly text

        # Store the result in the database along with the email
        conn = get_db_connection()
        conn.execute('INSERT INTO disease (username, email, pregnancies, glucose, blood_pressure, skin_thickness, insulin, bmi, dpf, age, prediction) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                     (username, email, num_preg, glucose_conc, diastolic_bp, thickness, insulin, bmi, dpf, age, prediction_result))
        conn.commit()
        conn.close()

        # Context to pass to the template
        context = {
            'num_preg': num_preg,
            'glucose_conc': glucose_conc,
            'diastolic_bp': diastolic_bp,
            'thickness': thickness,
            'insulin': insulin,
            'bmi': bmi,
            'dpf': dpf,
            'age': age,
            'prediction_result': prediction_result
        }

        return render_template('prediction_result.html', context=context)  # Redirect to a result page after prediction
    else:
        return render_template('prediction_form.html')  # Show the form when the method is GET

@app.route('/prediction')
def prediction_page():
    if 'logged_in' in session and session['logged_in']:
        return render_template('prediction.html')  # This will be the form where the user enters data
    else:
        return redirect('/login')

@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])  # Hash the password

        # Insert the new admin into the database
        conn = get_db_connection()
        conn.execute('INSERT INTO admin (name, email, password) VALUES (?, ?, ?)', 
                     (name, email, password))
        conn.commit()
        conn.close()

        # Show a success notification and redirect to the admin dashboard
        success_message = "Admin added successfully!"
        return render_template('admin_dashboard.html', success_message=success_message)

    return render_template('add_admin.html')  # Render the form for adding an admin


@app.route('/manage_users')
def manage_users():
    conn = get_db_connection()
    users = conn.execute('SELECT username, email FROM users').fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/total_predictions')
def total_predictions():
    conn = get_db_connection()
    total_predictions = conn.execute('SELECT COUNT(*) FROM disease').fetchone()[0]
    positive_predictions = conn.execute("SELECT COUNT(*) FROM disease WHERE prediction = 'Positive'").fetchone()[0]
    negative_predictions = conn.execute("SELECT COUNT(*) FROM disease WHERE prediction = 'Negative'").fetchone()[0]
    conn.close()
    return render_template('total_predictions.html', total_predictions=total_predictions, 
                           positive_predictions=positive_predictions, negative_predictions=negative_predictions)

@app.route('/reports')
def reports():
    conn = get_db_connection()
    reports = conn.execute('SELECT username,email,  prediction FROM disease').fetchall()
    conn.close()
    return render_template('reports.html', reports=reports)


if __name__ == '__main__':
    app.run(debug=True)
