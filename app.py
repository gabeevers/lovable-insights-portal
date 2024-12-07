from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database initialization
def init_db():
    conn = sqlite3.connect('finance.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        income REAL,
        risk_tolerance TEXT,
        financial_goals TEXT
    )''')
    
    # Expenses table
    c.execute('''CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        date TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Savings table
    c.execute('''CREATE TABLE IF NOT EXISTS savings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL NOT NULL,
        date TEXT NOT NULL,
        goal TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        income = request.form['income']
        risk_tolerance = request.form['risk_tolerance']
        financial_goals = request.form['financial_goals']
        
        conn = sqlite3.connect('finance.db')
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO users (username, password, email, income, risk_tolerance, financial_goals) VALUES (?, ?, ?, ?, ?, ?)',
                     (username, generate_password_hash(password), email, income, risk_tolerance, financial_goals))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('finance.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('finance.db')
    c = conn.cursor()
    
    # Get user data
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    # Get expenses
    c.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC LIMIT 5', (session['user_id'],))
    expenses = c.fetchall()
    
    # Get savings
    c.execute('SELECT * FROM savings WHERE user_id = ? ORDER BY date DESC LIMIT 5', (session['user_id'],))
    savings = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, expenses=expenses, savings=savings)

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        category = request.form['category']
        amount = request.form['amount']
        date = request.form['date']
        
        conn = sqlite3.connect('finance.db')
        c = conn.cursor()
        c.execute('INSERT INTO expenses (user_id, category, amount, date) VALUES (?, ?, ?, ?)',
                 (session['user_id'], category, amount, date))
        conn.commit()
        conn.close()
        
        flash('Expense added successfully!')
        return redirect(url_for('dashboard'))

@app.route('/add_saving', methods=['POST'])
@login_required
def add_saving():
    if request.method == 'POST':
        amount = request.form['amount']
        date = request.form['date']
        goal = request.form['goal']
        
        conn = sqlite3.connect('finance.db')
        c = conn.cursor()
        c.execute('INSERT INTO savings (user_id, amount, date, goal) VALUES (?, ?, ?, ?)',
                 (session['user_id'], amount, date, goal))
        conn.commit()
        conn.close()
        
        flash('Saving added successfully!')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)