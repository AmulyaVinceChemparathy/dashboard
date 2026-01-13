from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import pandas as pd
import os
import json
import hashlib
from datetime import datetime
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

app = FastAPI()
load_dotenv()
app.add_middleware(SessionMiddleware, secret_key="xxxx")
USERS_TABLE = os.getenv("USERS_TABLE", "users")

def get_connection():
    """Create a new MySQL connection using environment variables."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_DATABASE"),
        )
        return conn
    except Error as err:
        raise Exception(f"Database connection failed: {err}")

def ensure_users_table(conn):
    """Create the users table if it does not exist."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS `{USERS_TABLE}` (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    finally:
        cursor.close()

def create_user(username: str, password: str):
    """Register a new user with hashed password."""
    username = (username or "").strip()
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters long.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")

    conn = get_connection()
    cursor = conn.cursor()
    try:
        ensure_users_table(conn)
        cursor.execute(f"SELECT 1 FROM `{USERS_TABLE}` WHERE username = %s", (username,))
        if cursor.fetchone():
            raise ValueError("Username already exists.")

        password_hash = hash_password(password)
        cursor.execute(
            f"INSERT INTO `{USERS_TABLE}` (username, password_hash) VALUES (%s, %s)",
            (username, password_hash),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def get_denials_dataframe():
    """Fetch denials data using the provided SQL query."""
    conn = get_connection()
    try:
        query = ("SELECT CLINIC_NAME as Clinic, PATIENT_NAME as 'Pt Name',MRN as MRN, DOB as DOB,DOS as DOS, PAYER_NAME as Payer, PROCEDURE_CODE as CPT,REASON as Reason, CATEGORY as Category, DENIAL_DATE as  'Denial Date',USER_NAME as User, ROLE_ID FROM DAILY_DENIALS")
        df = pd.read_sql(query, conn)
    except Exception as exc:
        raise Exception(f"Error reading denials data: {exc}")
    finally:
        conn.close()
    
    if df.empty:
        raise Exception("No data returned from denials query")

    if "Category" not in df.columns:
        raise Exception("Expected 'Category' column in denials query result")

    df.rename(columns={"Category": "CATEGORY"}, inplace=True)
    return df

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(username: str, password: str) -> bool:
    """Validate user credentials against the users table."""
    username = (username or "").strip()
    if not username or not password:
        return False

    conn = None
    cursor = None
    try:
        conn = get_connection()
        ensure_users_table(conn)
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT password_hash FROM `{USERS_TABLE}` WHERE username = %s",
            (username,),
        )
        result = cursor.fetchone()
        if not result:
            return False
        stored_hash = result[0]
        return stored_hash == hash_password(password)
    except Exception as exc:
        print(f"verify_user error: {exc}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/test")
def test():
    """Simple test endpoint to verify server is running"""
    return {"status": "ok", "message": "Server is running"}

@app.get("/", response_class=HTMLResponse)
def homepage(request: Request):
    """Homepage with login form"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0px 10px 30px rgba(0,0,0,0.3);
                width: 350px;
            }
            h1 {
                text-align: center;
                color: #333;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .success-message {
                color: #155724;
                background: #d4edda;
                border: 1px solid #c3e6cb;
                padding: 12px;
                border-radius: 6px;
                margin-bottom: 20px;
                text-align: center;
                font-size: 14px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                color: #555;
                font-weight: bold;
            }
            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                box-sizing: border-box;
            }
            input[type="text"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #2c5282;
            }
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0px 5px 15px rgba(44, 82, 130, 0.4);
            }
            .error {
                color: red;
                text-align: center;
                margin-top: 10px;
                font-size: 14px;
            }
            .register-link {
                text-align: center;
                margin-top: 20px;
                color: #666;
                font-size: 14px;
            }
            .register-link a {
                color: #2c5282;
                text-decoration: none;
            }
            .register-link a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>Welcome</h1>
            {{SUCCESS_MESSAGE}}
            <form method="post" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="register-link">
                Don't have an account? <a href="/register">Register here</a>
            </div>
        </div>
    </body>
    </html>
    """
    success_html = ""
    if request.query_params.get("registered") == "1":
        success_html = '<div class="success-message">Account created successfully. Please sign in.</div>'
    html = html.replace("{{SUCCESS_MESSAGE}}", success_html)
    return HTMLResponse(content=html)

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handle login form submission"""
    if verify_user(username, password):
        request.session["authenticated"] = True
        request.session["username"] = username
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    else:
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .login-container {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0px 10px 30px rgba(0,0,0,0.3);
                    width: 350px;
                }
                h1 {
                    text-align: center;
                    color: #333;
                    margin-bottom: 30px;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 8px;
                    color: #555;
                    font-weight: bold;
                }
                input[type="text"],
                input[type="password"] {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #ddd;
                    border-radius: 5px;
                    font-size: 16px;
                    box-sizing: border-box;
                }
                input[type="text"]:focus,
                input[type="password"]:focus {
                    outline: none;
                    border-color: #2c5282;
                }
                button {
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                    color: white;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                    transition: transform 0.2s;
                }
                button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0px 5px 15px rgba(44, 82, 130, 0.4);
                }
                .error {
                    color: red;
                    text-align: center;
                    margin-top: 10px;
                    font-size: 14px;
                    padding: 10px;
                    background: #ffe6e6;
                    border-radius: 5px;
                }
                .register-link {
                    text-align: center;
                    margin-top: 20px;
                    color: #666;
                    font-size: 14px;
                }
                .register-link a {
                    color: #2c5282;
                    text-decoration: none;
                }
                .register-link a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>Welcome</h1>
                <div class="error">Invalid username or password. Please try again.</div>
                <form method="post" action="/login">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
                <div class="register-link">
                    Don't have an account? <a href="/register">Register here</a>
                </div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html)

def render_register_form(error_message: str = "", username: str = "") -> str:
    """Generate the register page HTML with optional error message."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .register-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0px 10px 30px rgba(0,0,0,0.3);
                width: 380px;
            }
            h1 {
                text-align: center;
                color: #333;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                color: #555;
                font-weight: bold;
            }
            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                box-sizing: border-box;
            }
            input[type="text"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #2c5282;
            }
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0px 5px 15px rgba(44, 82, 130, 0.4);
            }
            .error {
                color: #721c24;
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                padding: 12px;
                border-radius: 6px;
                margin-bottom: 15px;
                text-align: center;
                font-size: 14px;
            }
            .login-link {
                text-align: center;
                margin-top: 20px;
                color: #666;
                font-size: 14px;
            }
            .login-link a {
                color: #2c5282;
                text-decoration: none;
            }
            .login-link a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="register-container">
            <h1>Create Account</h1>
            {{ERROR_BLOCK}}
            <form method="post" action="/register">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" value="{{USERNAME_VALUE}}" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <button type="submit">Register</button>
            </form>
            <div class="login-link">
                Already have an account? <a href="/">Back to login</a>
            </div>
        </div>
    </body>
    </html>
    """
    error_block = ""
    if error_message:
        error_block = f'<div class="error">{error_message}</div>'
    html = html.replace("{{ERROR_BLOCK}}", error_block)
    html = html.replace("{{USERNAME_VALUE}}", username or "")
    return html

@app.get("/register", response_class=HTMLResponse)
def register_page():
    """Display the registration form."""
    return HTMLResponse(content=render_register_form())

@app.post("/register")
async def register_user(
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Handle new user registration."""
    username = (username or "").strip()
    if password != confirm_password:
        return HTMLResponse(
            content=render_register_form("Passwords do not match.", username),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        create_user(username, password)
    except ValueError as exc:
        return HTMLResponse(
            content=render_register_form(str(exc), username),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:
        print(f"register_user error: {exc}")
        return HTMLResponse(
            content=render_register_form("Registration failed. Please try again.", username),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return RedirectResponse(url="/?registered=1", status_code=status.HTTP_302_FOUND)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    """Dashboard page with sidebar and content area"""
    # Check if user is authenticated
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: Arial, sans-serif;
                background-color: #1e3a5f;
                height: 100vh;
                display: flex;
            }
            .sidebar {
                width: 25%;
                background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                color: white;
                padding: 20px;
                overflow-y: auto;
                transition: transform 0.3s ease, width 0.3s ease;
                position: relative;
            }
            .sidebar.collapsed {
                transform: translateX(-100%);
                width: 0;
                padding: 0;
                overflow: hidden;
            }
            .menu-toggle-btn {
                display: none;
                position: fixed;
                left: 20px;
                top: 50%;
                transform: translateY(-50%);
                z-index: 1000;
                background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
                color: white;
                border: none;
                padding: 15px 20px;
                border-radius: 0 8px 8px 0;
                cursor: pointer;
                font-size: 18px;
                font-weight: bold;
                box-shadow: 2px 0 8px rgba(0,0,0,0.2);
                transition: all 0.3s ease;
            }
            .menu-toggle-btn:hover {
                background: linear-gradient(135deg, #2c5282 0%, #1e3a5f 100%);
                padding-left: 25px;
            }
            .menu-toggle-btn.visible {
                display: block;
            }
            .sidebar h2 {
                margin-bottom: 30px;
                font-size: 24px;
            }
            .menu-item {
                margin-bottom: 10px;
            }
            .menu-header {
                padding: 15px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                cursor: pointer;
                font-weight: bold;
                font-size: 18px;
                transition: background 0.3s;
            }
            .menu-header:hover {
                background: rgba(255, 255, 255, 0.2);
            }
            .menu-header.active {
                background: rgba(255, 255, 255, 0.3);
            }
            .submenu {
                display: none;
                margin-top: 10px;
                padding-left: 10px;
            }
            .submenu.active {
                display: block;
            }
            .submenu-item {
                padding: 12px 15px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                margin-bottom: 8px;
                cursor: pointer;
                transition: background 0.3s;
            }
            .submenu-item:hover {
                background: rgba(255, 255, 255, 0.2);
            }
            .submenu-item.active {
                background: rgba(255, 255, 255, 0.3);
            }
            .logout-link {
                margin-top: 30px;
                padding: 15px;
                text-align: center;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                cursor: pointer;
                font-weight: bold;
                font-size: 18px;
                transition: background 0.3s;
            }
            .logout-link a {
                color: white;
                text-decoration: none;
                font-size: 18px;
                font-weight: bold;
            }
            .logout-link:hover {
                background: rgba(255, 255, 255, 0.2);
            }
            .logout-link a:hover {
                text-decoration: none;
            }
            .content-area {
                width: 75%;
                padding: 20px;
                overflow-y: auto;
                background-color: #f0f4f8;
                transition: width 0.3s ease;
            }
            .content-area.expanded {
                width: 100%;
            }
            .content-placeholder {
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100%;
                color: #2c5282;
                font-size: 18px;
            }
            #chart-container {
                display: none;
            }
            #chart-container.active {
                display: block;
            }
            #chart-container #chart {
                width: 100%;
                margin: auto;
                min-height: 600px;
            }
            .content-area.expanded #chart-container #chart {
                width: 100%;
            }
            #chart-container #popup {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: white;
                z-index: 1000;
                overflow: hidden;
            }
            #chart-container #popup-header {
                position: sticky;
                top: 0;
                background: white;
                padding: 15px 20px;
                border-bottom: 2px solid #2c5282;
                display: flex;
                justify-content: space-between;
                align-items: center;
                z-index: 1001;
                box-shadow: 0px 2px 5px rgba(0,0,0,0.1);
            }
            #chart-container #popup-header h3 {
                margin: 0;
                color: #1e3a5f;
                font-size: 24px;
            }
            #chart-container #popup-buttons {
                display: flex;
                gap: 10px;
            }
            #chart-container #close, #chart-container #download {
                background-color: #ff4d4d;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
                font-weight: bold;
                transition: background-color 0.3s;
            }
            #chart-container #close:hover {
                background-color: #ff3333;
            }
            #chart-container #download {
                background-color: #28a745;
            }
            #chart-container #download:hover {
                background-color: #218838;
            }
            #chart-container #popup-content {
                padding: 20px;
                overflow-y: auto;
                height: calc(100% - 80px);
            }
            #chart-container table {
                margin-top: 10px;
                border-collapse: collapse;
                width: 100%;
            }
            #chart-container th, #chart-container td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            #chart-container th {
                background-color: #f2f2f2;
                text-align: left;
            }
            .loading-spinner {
                display: inline-block;
                width: 40px;
                height: 40px;
                border: 4px solid #f3f3f3;
                border-top: 4px solid #1e3a5f;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .loading-container {
                text-align: center;
                padding: 40px;
            }
            .loading-container p {
                color: #2c5282;
                font-size: 16px;
                margin-top: 15px;
            }
        </style>
    </head>
    <body>
        <button id="menuToggleBtn" class="menu-toggle-btn" onclick="toggleMenu()">☰ Menu</button>
        <div class="sidebar" id="sidebar">
            <h2>Menu</h2>
            <div class="menu-item">
                <div class="menu-header" onclick="toggleSubmenu()">Denials</div>
                <div class="submenu" id="denialsSubmenu">
                    <div class="submenu-item" onclick="loadDenialChart()">Denial</div>
                    <div class="submenu-item" onclick="loadDenialsComparison()">Denials Comparison</div>
                </div>
            </div>
            <div class="menu-item">
                <div class="menu-header" onclick="toggleComparisonSubmenu()">Comparison</div>
                <div class="submenu" id="comparisonSubmenu">
                    <div class="submenu-item" onclick="loadComparison('daily')">Daily</div>
                    <div class="submenu-item" onclick="loadComparison('biweekly')">Biweekly</div>
                    <div class="submenu-item" onclick="loadComparison('monthly')">Monthly</div>
                </div>
            </div>
            <div class="menu-item">
                <div class="menu-header" onclick="toggleClarificationSubmenu()">Clarification</div>
                <div class="submenu" id="clarificationSubmenu">
                    <div class="submenu-item" onclick="loadClarificationByAging()">By Aging</div>
                    <div class="submenu-item" onclick="loadClarificationType()">Clarification Type</div>
                </div>
            </div>
            <div class="menu-item">
                <div class="menu-header" onclick="togglePerformanceSubmenu()">Performance Analysis</div>
                <div class="submenu" id="performanceSubmenu">
                    <div class="submenu-item" onclick="loadPerformanceAnalysis()">Performance Analysis</div>
                    <div class="submenu-item" onclick="loadCountComparison()">Count Comparison</div>
                </div>
            </div>
            <div class="logout-link">
                <form method="post" action="/logout" style="margin: 0; padding: 0;">
                    <button type="submit" style="background: none; border: none; color: white; font-size: 18px; font-weight: bold; cursor: pointer; width: 100%; padding: 0;">
                        Logout
                    </button>
                </form>
            </div>
        </div>
        <div class="content-area">
            <div class="content-placeholder" id="placeholder">
                Select an option from the menu to view content
            </div>
            <div id="chart-container"></div>
        </div>
        <script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
        <script>
            // Menu collapse/expand functionality
            function toggleMenu() {
                var sidebar = document.getElementById('sidebar');
                var contentArea = document.querySelector('.content-area');
                var menuToggleBtn = document.getElementById('menuToggleBtn');
                
                if (sidebar.classList.contains('collapsed')) {
                    // Expand menu
                    sidebar.classList.remove('collapsed');
                    contentArea.classList.remove('expanded');
                    menuToggleBtn.classList.remove('visible');
                } else {
                    // Collapse menu
                    sidebar.classList.add('collapsed');
                    contentArea.classList.add('expanded');
                    menuToggleBtn.classList.add('visible');
                }
                
                // Resize charts if any are active
                setTimeout(function() {
                    var chartDiv = document.getElementById('chart');
                    if (chartDiv && chartDiv.data) {
                        Plotly.Plots.resize(chartDiv);
                    }
                }, 350);
            }
            
            function collapseMenu() {
                var sidebar = document.getElementById('sidebar');
                var contentArea = document.querySelector('.content-area');
                var menuToggleBtn = document.getElementById('menuToggleBtn');
                
                if (!sidebar.classList.contains('collapsed')) {
                    sidebar.classList.add('collapsed');
                    contentArea.classList.add('expanded');
                    menuToggleBtn.classList.add('visible');
                    
                    // Resize charts after collapse
                    setTimeout(function() {
                        var chartDiv = document.getElementById('chart');
                        if (chartDiv && chartDiv.data) {
                            Plotly.Plots.resize(chartDiv);
                        }
                    }, 350);
                }
            }
            
            // Define menu toggle functions first
            function toggleSubmenu() {
                var submenu = document.getElementById('denialsSubmenu');
                if (submenu) {
                submenu.classList.toggle('active');
                }
            }
            
            function toggleComparisonSubmenu() {
                var submenu = document.getElementById('comparisonSubmenu');
                if (submenu) {
                submenu.classList.toggle('active');
                }
            }
            
            function toggleClarificationSubmenu() {
                var submenu = document.getElementById('clarificationSubmenu');
                if (submenu) {
                    submenu.classList.toggle('active');
                }
            }
            
            function togglePerformanceSubmenu() {
                var submenu = document.getElementById('performanceSubmenu');
                if (submenu) {
                    submenu.classList.toggle('active');
                }
            }
            
            function loadComparison(period) {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                // Add active class to Comparison menu header
                event.target.closest('.menu-item').querySelector('.menu-header').classList.add('active');
                
                // Collapse menu
                collapseMenu();
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show selector UI
                showComparisonSelector(period, chartContainer);
            }
            
            function showComparisonSelector(period, chartContainer) {
                var periodLabel = period.charAt(0).toUpperCase() + period.slice(1);
                var selectorHtml = '';
                
                if (period === 'daily') {
                    // Daily shows yesterday's data - no selector needed, just load button
                    selectorHtml = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">' + periodLabel + ' Comparison</h2><p style="color: #2c5282; font-size: 16px; margin-bottom: 20px;">Showing yesterdays denial data</p><button id="loadDailyBtn" data-period="' + period + '" style="padding: 10px 20px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;">Load Chart</button></div>';
                } else if (period === 'biweekly') {
                    // Biweekly shows data for the other half of current month
                    selectorHtml = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">' + periodLabel + ' Comparison</h2><p style="color: #2c5282; font-size: 16px; margin-bottom: 20px;">Showing data for the other half of current month</p><button id="loadBiweeklyBtn" data-period="' + period + '" style="padding: 10px 20px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;">Load Chart</button></div>';
                } else if (period === 'monthly') {
                    // Monthly shows last month's data - no selector needed, just load button
                    selectorHtml = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">' + periodLabel + ' Comparison</h2><p style="color: #2c5282; font-size: 16px; margin-bottom: 20px;">Showing last months denial data</p><button id="loadMonthlyBtn" data-period="' + period + '" style="padding: 10px 20px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;">Load Chart</button></div>';
                }
                chartContainer.innerHTML = selectorHtml + '<div id="chart"></div><div id="popup"><div id="popup-header"><h3 id="popup-title"></h3><div id="popup-buttons"><button id="download">Download Excel</button><button id="close">Close</button></div></div><div id="popup-content"></div></div>';
                
                // Attach event listeners to buttons
                setTimeout(function() {
                    var btn = document.getElementById('loadDailyBtn') || document.getElementById('loadMonthlyBtn') || document.getElementById('loadBiweeklyBtn');
                    if (btn) {
                        btn.addEventListener('click', function() {
                            fetchComparisonData(period);
                        });
                    }
                }, 100);
            }
            
            function fetchComparisonData(period) {
                var chartContainer = document.getElementById('chart-container');
                if (!chartContainer) {
                    console.error('Chart container not found');
                    return;
                }
                
                // Disable the load button
                var btn = document.getElementById('loadDailyBtn') || document.getElementById('loadMonthlyBtn') || document.getElementById('loadBiweeklyBtn');
                if (btn) {
                    btn.disabled = true;
                    btn.style.opacity = '0.6';
                    btn.style.cursor = 'not-allowed';
                }
                
                // Show loading spinner in chart div
                var chartDiv = document.getElementById('chart');
                if (chartDiv) {
                    chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading chart data...</p></div>';
                } else {
                    // If chart div doesn't exist yet, preserve existing structure and add loading
                    var selectorDiv = chartContainer.querySelector('div[style*="text-align"]');
                    if (selectorDiv) {
                        chartContainer.innerHTML = selectorDiv.outerHTML + '<div id="chart"><div class="loading-container"><div class="loading-spinner"></div><p>Loading chart data...</p></div></div><div id="popup"><div id="popup-header"><h3 id="popup-title"></h3><div id="popup-buttons"><button id="download">Download Excel</button><button id="close">Close</button></div></div><div id="popup-content"></div></div>';
                    }
                }
                
                var url = '/comparison-data?period=' + encodeURIComponent(period);
                fetch(url)
                    .then(function(response) {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        return response.json();
                    })
                    .then(function(data) {
                        // Re-enable the button
                        if (btn) {
                            btn.disabled = false;
                            btn.style.opacity = '1';
                            btn.style.cursor = 'pointer';
                        }
                        
                        if (data.error) {
                            var errorDiv = document.getElementById('chart');
                            if (errorDiv) {
                                errorDiv.innerHTML = '<p style="color: red; text-align: center; padding: 20px;">Error: ' + data.error + '</p>';
                            } else {
                                chartContainer.innerHTML = '<p style="color: red; text-align: center; padding: 20px;">Error: ' + data.error + '</p>';
                            }
                        } else {
                            renderComparisonChart(data, period);
                        }
                    })
                    .catch(function(error) {
                        // Re-enable the button
                        if (btn) {
                            btn.disabled = false;
                            btn.style.opacity = '1';
                            btn.style.cursor = 'pointer';
                        }
                        
                        console.error('Error loading comparison chart:', error);
                        var errorDiv = document.getElementById('chart');
                        if (errorDiv) {
                            errorDiv.innerHTML = '<p style="color: red; text-align: center; padding: 20px;">Error loading comparison chart data: ' + error.message + '</p>';
                        } else {
                            chartContainer.innerHTML = '<p style="color: red; text-align: center; padding: 20px;">Error loading comparison chart data: ' + error.message + '</p>';
                        }
                });
            }
            
            function loadDenialChart() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                
                // Collapse menu
                collapseMenu();
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show loading spinner
                chartContainer.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading denial chart data...</p></div>';
                
                // Always reload the chart
                fetch('/button-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartContainer.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading chart:', error);
                        chartContainer.innerHTML = '<p style="color: red;">Error loading chart data</p>';
                    });
            }
            
            function loadDenialsComparison() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                // Add active class to Denials menu header
                event.target.closest('.menu-item').querySelector('.menu-header').classList.add('active');
                
                // Collapse menu
                collapseMenu();
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show buttons for different comparison options
                chartContainer.innerHTML = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 20px; font-weight: 600;">Denials Comparison</h2><div style="display: flex; gap: 15px; justify-content: center; margin-bottom: 20px;"><button id="denialsCurrentPrevBtn" style="background-color: #2c5282; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; transition: background-color 0.3s;">Current vs Previous Month</button><button id="denialsBiweeklyBtn" style="background-color: #2c5282; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; transition: background-color 0.3s;">Biweekly for 3 Months</button><button id="denialsMonthlyBtn" style="background-color: #2c5282; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; transition: background-color 0.3s;">Monthly for 6 Months</button></div><div id="chart"></div></div>';
                
                // Add event listeners
                var currentPrevBtn = document.getElementById('denialsCurrentPrevBtn');
                var biweeklyBtn = document.getElementById('denialsBiweeklyBtn');
                var monthlyBtn = document.getElementById('denialsMonthlyBtn');
                
                if (currentPrevBtn) {
                    currentPrevBtn.onclick = function() {
                        loadDenialsCurrentPreviousComparison();
                    };
                    currentPrevBtn.onmouseover = function() {
                        this.style.backgroundColor = '#1e3a5f';
                    };
                    currentPrevBtn.onmouseout = function() {
                        this.style.backgroundColor = '#2c5282';
                    };
                }
                
                if (biweeklyBtn) {
                    biweeklyBtn.onclick = function() {
                        loadDenialsBiweeklyComparison();
                    };
                    biweeklyBtn.onmouseover = function() {
                        this.style.backgroundColor = '#1e3a5f';
                    };
                    biweeklyBtn.onmouseout = function() {
                        this.style.backgroundColor = '#2c5282';
                    };
                }
                
                if (monthlyBtn) {
                    monthlyBtn.onclick = function() {
                        loadDenialsMonthlyComparison();
                    };
                    monthlyBtn.onmouseover = function() {
                        this.style.backgroundColor = '#1e3a5f';
                    };
                    monthlyBtn.onmouseout = function() {
                        this.style.backgroundColor = '#2c5282';
                    };
                }
            }
            
            function loadDenialsCurrentPreviousComparison() {
                var chartContainer = document.getElementById('chart-container');
                var chartDiv = document.getElementById('chart');
                if (!chartDiv) {
                    // If chart div doesn't exist, preserve the buttons structure
                    var buttonsDiv = chartContainer.querySelector('div[style*="display: flex"]');
                    chartContainer.innerHTML = (buttonsDiv ? buttonsDiv.outerHTML : '') + '<div id="chart"></div>';
                    chartDiv = document.getElementById('chart');
                }
                chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading denials comparison data...</p></div>';
                
                fetch('/denials-comparison-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderDenialsComparisonChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading denials comparison:', error);
                        chartDiv.innerHTML = '<p style="color: red;">Error loading denials comparison data</p>';
                    });
            }
            
            function loadDenialsBiweeklyComparison() {
                var chartContainer = document.getElementById('chart-container');
                var chartDiv = document.getElementById('chart');
                if (!chartDiv) {
                    var buttonsDiv = chartContainer.querySelector('div[style*="display: flex"]');
                    chartContainer.innerHTML = (buttonsDiv ? buttonsDiv.outerHTML : '') + '<div id="chart"></div>';
                    chartDiv = document.getElementById('chart');
                }
                chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading biweekly comparison data...</p></div>';
                
                fetch('/denials-biweekly-comparison-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderDenialsBiweeklyComparisonChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading biweekly comparison:', error);
                        chartDiv.innerHTML = '<p style="color: red;">Error loading biweekly comparison data</p>';
                    });
            }
            
            function loadDenialsMonthlyComparison() {
                var chartContainer = document.getElementById('chart-container');
                var chartDiv = document.getElementById('chart');
                if (!chartDiv) {
                    var buttonsDiv = chartContainer.querySelector('div[style*="display: flex"]');
                    chartContainer.innerHTML = (buttonsDiv ? buttonsDiv.outerHTML : '') + '<div id="chart"></div>';
                    chartDiv = document.getElementById('chart');
                }
                chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading monthly comparison data...</p></div>';
                
                fetch('/denials-monthly-comparison-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderDenialsMonthlyComparisonChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading monthly comparison:', error);
                        chartDiv.innerHTML = '<p style="color: red;">Error loading monthly comparison data</p>';
                    });
            }
            
            function loadClarificationByAging() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                // Add active class to Clarification menu header
                event.target.closest('.menu-item').querySelector('.menu-header').classList.add('active');
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show loading spinner
                chartContainer.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading clarification grouping data...</p></div>';
                
                // Fetch clarification grouping data (same as Clarification Grouping button)
                fetch('/clarification-grouping-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartContainer.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderClarificationChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading clarification grouping:', error);
                        chartContainer.innerHTML = '<p style="color: red;">Error loading clarification grouping data</p>';
                    });
            }
            
            /*
            // COMMENTED OUT - Original clarification by aging function
            */
            
            function loadClarificationType() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                // Add active class to Clarification menu header
                event.target.closest('.menu-item').querySelector('.menu-header').classList.add('active');
                
                // Collapse menu
                collapseMenu();
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show loading spinner
                chartContainer.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading clarification type data...</p></div>';
                
                // Fetch clarification type data
                fetch('/clarification-type-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartContainer.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderClarificationTypeChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading clarification type:', error);
                        chartContainer.innerHTML = '<p style="color: red;">Error loading clarification type data</p>';
                    });
            }
            
            function loadPerformanceAnalysis() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                // Add active class to Performance Analysis menu header
                event.target.closest('.menu-item').querySelector('.menu-header').classList.add('active');
                
                // Collapse menu
                collapseMenu();
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show loading spinner
                chartContainer.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading performance analysis data...</p></div>';
                
                // Fetch users by role
                fetch('/performance-users')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartContainer.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderPerformanceAnalysis(data, chartContainer);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading performance analysis:', error);
                        chartContainer.innerHTML = '<p style="color: red;">Error loading performance analysis data</p>';
                    });
            }
            
            function renderPerformanceAnalysis(usersData, chartContainer) {
                var billingTeam = usersData.billing_team || [];
                var arTeam = usersData.ar_team || [];
                
                // Create HTML with two buttons and dropdowns
                var html = '<div style="text-align: center; margin-bottom: 30px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 20px; font-weight: 600;">Performance Analysis</h2>';
                html += '<div style="display: flex; gap: 30px; justify-content: center; margin-bottom: 30px;">';
                
                // Billing Team button and dropdown
                html += '<div style="position: relative; display: inline-block;">';
                html += '<button id="billingTeamBtn" style="padding: 12px 24px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: bold;">Billing Team ▼</button>';
                html += '<div id="billingDropdown" style="display: none; position: absolute; background: white; min-width: 200px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1000; border-radius: 5px; margin-top: 5px; max-height: 300px; overflow-y: auto;">';
                if (billingTeam.length === 0) {
                    html += '<div style="padding: 10px; color: #666;">No members found</div>';
                } else {
                    billingTeam.forEach(function(member) {
                        html += '<div class="dropdown-item" data-team="billing" data-username="' + member.replace(/"/g, '&quot;') + '" style="padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #eee; color: #1e3a5f;">' + member + '</div>';
                    });
                }
                html += '</div></div>';
                
                // A R Team button and dropdown
                html += '<div style="position: relative; display: inline-block;">';
                html += '<button id="arTeamBtn" style="padding: 12px 24px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: bold;">A R Team ▼</button>';
                html += '<div id="arDropdown" style="display: none; position: absolute; background: white; min-width: 200px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1000; border-radius: 5px; margin-top: 5px; max-height: 300px; overflow-y: auto;">';
                if (arTeam.length === 0) {
                    html += '<div style="padding: 10px; color: #666;">No members found</div>';
                } else {
                    arTeam.forEach(function(member) {
                        html += '<div class="dropdown-item" data-team="ar" data-username="' + member.replace(/"/g, '&quot;') + '" style="padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #eee; color: #1e3a5f;">' + member + '</div>';
                    });
                }
                html += '</div></div>';
                
                html += '</div></div>';
                html += '<div id="chart"></div>';
                html += '<div id="popup"><div id="popup-header"><h3 id="popup-title"></h3><div id="popup-buttons"><button id="download">Download Excel</button><button id="close">Close</button></div></div><div id="popup-content"></div></div>';
                
                chartContainer.innerHTML = html;
                
                // Setup dropdown toggle functionality
                var billingBtn = document.getElementById('billingTeamBtn');
                var arBtn = document.getElementById('arTeamBtn');
                var billingDropdown = document.getElementById('billingDropdown');
                var arDropdown = document.getElementById('arDropdown');
                
                billingBtn.onclick = function(e) {
                    e.stopPropagation();
                    arDropdown.style.display = 'none';
                    billingDropdown.style.display = billingDropdown.style.display === 'none' ? 'block' : 'none';
                };
                
                arBtn.onclick = function(e) {
                    e.stopPropagation();
                    billingDropdown.style.display = 'none';
                    arDropdown.style.display = arDropdown.style.display === 'none' ? 'block' : 'none';
                };
                
                // Close dropdowns when clicking outside
                document.addEventListener('click', function(e) {
                    if (!billingBtn.contains(e.target) && !billingDropdown.contains(e.target)) {
                        billingDropdown.style.display = 'none';
                    }
                    if (!arBtn.contains(e.target) && !arDropdown.contains(e.target)) {
                        arDropdown.style.display = 'none';
                    }
                });
                
                // Handle member selection
                var dropdownItems = document.querySelectorAll('.dropdown-item');
                dropdownItems.forEach(function(item) {
                    item.onclick = function() {
                        var username = this.getAttribute('data-username');
                        billingDropdown.style.display = 'none';
                        arDropdown.style.display = 'none';
                        loadUserDenialsChart(username);
                    };
                    // Add hover effect using JavaScript instead of inline handlers
                    item.onmouseover = function() {
                        this.style.backgroundColor = '#f0f4f8';
                    };
                    item.onmouseout = function() {
                        this.style.backgroundColor = 'white';
                    };
                });
            }
            
            function loadUserDenialsChart(username) {
                var chartContainer = document.getElementById('chart-container');
                var chartDiv = document.getElementById('chart');
                
                // Show loading spinner
                chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading denial data for ' + username + '...</p></div>';
                
                // Fetch user denial data
                fetch('/user-denials-data?username=' + encodeURIComponent(username))
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderUserDenialsChart(data, username);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading user denials:', error);
                        chartDiv.innerHTML = '<p style="color: red;">Error loading user denial data</p>';
                    });
            }
            
            function renderUserDenialsChart(data, username) {
                var chartContainer = document.getElementById('chart-container');
                var chartDiv = document.getElementById('chart');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderUserDenialsChart(data, username);
                    }, 100);
                    return;
                }
                
                // Clear chart div
                chartDiv.innerHTML = '';
                
                // Extract data
                var categories = data.categories || [];
                var counts = data.counts || [];
                var labelsWithCounts = data.labels_with_counts || [];
                var tableData = data.table_data || {};
                
                if (categories.length === 0) {
                    chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No denial data available for ' + username + '.</p>';
                    return;
                }
                
                // Create color map (same as denials chart)
                var colorMap = {
                    "Inactive or Wrong policy Information": "#dd7e6b",
                    "Medicare paid more than Medicaid": "#f9cb9c",
                    "Incorrect/Invalid DOS": "#ffe599",
                    "TFL/Appeal time limit expired or not allowed": "#e1cfca",
                    "Missing or Invalid ICD/CPT code/Modifier/POS": "#a2c4c9",
                    "Provider enrollment issue": "#a4c2f4",
                    "Out of network": "#b4a7d6",
                    "Need additional information needed": "#d5a6bd",
                    "Non covered service": "#ea9999",
                    "Incorrect Billing": "#dbe098",
                    "Bundled service": "#bcc07b",
                    "Other": "#808080"
                };
                
                // Create color array based on classification order
                var vibrantColors = categories.map(function(cat) {
                    return colorMap[cat.trim()] || '#808080';
                });
                
                var chartData = [{
                    type: "pie",
                    labels: labelsWithCounts,
                    values: counts,
                    textinfo: "label+percent",
                    hoverinfo: "label+value",
                    textposition: "outside",
                    automargin: true,
                    marker: { 
                        colors: vibrantColors,
                        line: { color: "#ffffff", width: 2 }
                    },
                    domain: { x: [0, 0.6], y: [0.3, 1] },
                    name: ""
                }];
                
                var layout = {
                    height: 700,
                    width: 1300,
                    margin: { l: 0, r: 0, t: 80, b: 0 },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: { 
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 14
                    },
                    showlegend: true,
                    legend: {
                        x: 0.75,
                        y: 1,
                        xanchor: "left",
                        yanchor: "top",
                        font: { 
                            size: 16,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        },
                        traceorder: "normal",
                        bgcolor: 'rgba(255,255,255,0.8)',
                        bordercolor: '#2c5282',
                        borderwidth: 1
                    },
                    title: {
                        text: 'Denials by Category - ' + username,
                        font: {
                            size: 20,
                            color: '#1e3a5f'
                        }
                    }
                };
                
                // Render the chart
                Plotly.newPlot("chart", chartData, layout);
                
                // Setup popup functionality (same as denials chart)
                var popup = document.getElementById("popup");
                var popupContent = document.getElementById("popup-content");
                var popupTitle = document.getElementById("popup-title");
                var closeBtn = document.getElementById("close");
                var downloadBtn = document.getElementById("download");
                var currentCategory = "";
                
                // Function to download table as Excel (same as denials chart)
                // Function to download table as Excel (same as denials chart)
function downloadTableAsExcel() {
    var table = popupContent.querySelector('table');
    if (!table) {
        alert('No table found to download');
        return;
    }

    var wb = XLSX.utils.book_new();
    var ws = XLSX.utils.table_to_sheet(table);

    // Convert ALL numbers and dates to strings, and left-align everything
    var range = XLSX.utils.decode_range(ws['!ref']);

    // Convert ALL cells to strings and left-align
    for (var R = 0; R <= range.e.r; ++R) {
        for (var C = range.s.c; C <= range.e.c; ++C) {
            var cellAddress = XLSX.utils.encode_cell({ r: R, c: C });

            if (!ws[cellAddress]) {
                ws[cellAddress] = {};
            }

            var cell = ws[cellAddress];

            if (cell && cell.v !== null && cell.v !== undefined) {

                // ✅ FIX: format dates BEFORE converting to string
                if (typeof cell.v === 'number' && cell.z && cell.z.toLowerCase().includes('d')) {
                    var d = XLSX.SSF.parse_date_code(cell.v);
                    cell.v =
                        String(d.m).padStart(2, '0') + '/' +
                        String(d.d).padStart(2, '0') + '/' +
                        d.y;
                } else {
                    cell.v = String(cell.v);
                }

                cell.t = 's'; // string type
                if (cell.z) delete cell.z; // remove any date format
            }

            // Left alignment for all cells
            if (!cell.s) cell.s = {};
            if (!cell.s.alignment) cell.s.alignment = {};
            cell.s.alignment.horizontal = 'left';
            cell.s.alignment.vertical = 'top';
            cell.s.alignment.wrapText = false;
        }
    }

    // Auto column width
    if (!ws['!cols']) ws['!cols'] = [];

    for (var C = range.s.c; C <= range.e.c; ++C) {
        var maxWidth = 10;

        var headerCell = XLSX.utils.encode_cell({ r: 0, c: C });
        if (ws[headerCell] && ws[headerCell].v) {
            maxWidth = Math.max(maxWidth, String(ws[headerCell].v).length);
        }

        for (var R = 1; R <= range.e.r; ++R) {
            var cellAddress = XLSX.utils.encode_cell({ r: R, c: C });
            if (ws[cellAddress] && ws[cellAddress].v !== null && ws[cellAddress].v !== undefined) {
                maxWidth = Math.max(maxWidth, String(ws[cellAddress].v).length);
            }
        }

        ws['!cols'][C] = { wch: maxWidth + 3 };
    }

    XLSX.utils.book_append_sheet(wb, ws, "Data");

    var filename =
        username.replace(/[^a-z0-9]/gi, '_') + '_' +
        currentCategory.replace(/[^a-z0-9]/gi, '_') + '_' +
        new Date().toISOString().split('T')[0] +
        '.xlsx';

    XLSX.writeFile(wb, filename);
}

                
                // Click handler for pie chart slices
                document.getElementById("chart").on('plotly_click', function(evt) {
                    var pointIndex = evt.points[0].pointNumber;
                    var category = categories[pointIndex];
                    currentCategory = category;
                    popupTitle.textContent = category + ' - ' + username;
                    
                    // Show popup with loading spinner
                    popup.style.display = "block";
                    popupContent.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading table data...</p></div>';
                    
                    // Load table data after a brief delay
                    setTimeout(function() {
                        popupContent.innerHTML = tableData[category] || '<p>No data available for this category</p>';
                    }, 300);
                });
                
                closeBtn.onclick = function() {
                    popup.style.display = "none";
                };
                
                downloadBtn.onclick = function() {
                    downloadTableAsExcel();
                };
            }
            
            function loadCountComparison() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                // Add active class to Performance Analysis menu header
                event.target.closest('.menu-item').querySelector('.menu-header').classList.add('active');
                
                // Collapse menu
                collapseMenu();
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show loading spinner
                chartContainer.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading count comparison data...</p></div>';
                
                // Fetch users by role
                fetch('/performance-users')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartContainer.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderCountComparison(data, chartContainer);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading count comparison:', error);
                        chartContainer.innerHTML = '<p style="color: red;">Error loading count comparison data</p>';
                    });
            }
            
            function renderCountComparison(usersData, chartContainer) {
                var billingTeam = usersData.billing_team || [];
                var arTeam = usersData.ar_team || [];
                
                // Create HTML with two buttons and dropdowns
                var html = '<div style="text-align: center; margin-bottom: 30px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 20px; font-weight: 600;">Count Comparison</h2>';
                html += '<div style="display: flex; gap: 30px; justify-content: center; margin-bottom: 30px;">';
                
                // Billing Team button and dropdown
                html += '<div style="position: relative; display: inline-block;">';
                html += '<button id="billingTeamBtn" style="padding: 12px 24px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: bold;">Billing Team ▼</button>';
                html += '<div id="billingDropdown" style="display: none; position: absolute; background: white; min-width: 200px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1000; border-radius: 5px; margin-top: 5px; max-height: 300px; overflow-y: auto;">';
                if (billingTeam.length === 0) {
                    html += '<div style="padding: 10px; color: #666;">No members found</div>';
                } else {
                    billingTeam.forEach(function(member) {
                        html += '<div class="dropdown-item" data-team="billing" data-username="' + member.replace(/"/g, '&quot;') + '" style="padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #eee; color: #1e3a5f;">' + member + '</div>';
                    });
                }
                html += '</div></div>';
                
                // A R Team button and dropdown
                html += '<div style="position: relative; display: inline-block;">';
                html += '<button id="arTeamBtn" style="padding: 12px 24px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: bold;">A R Team ▼</button>';
                html += '<div id="arDropdown" style="display: none; position: absolute; background: white; min-width: 200px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1000; border-radius: 5px; margin-top: 5px; max-height: 300px; overflow-y: auto;">';
                if (arTeam.length === 0) {
                    html += '<div style="padding: 10px; color: #666;">No members found</div>';
                } else {
                    arTeam.forEach(function(member) {
                        html += '<div class="dropdown-item" data-team="ar" data-username="' + member.replace(/"/g, '&quot;') + '" style="padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #eee; color: #1e3a5f;">' + member + '</div>';
                    });
                }
                html += '</div></div>';
                
                html += '</div></div>';
                html += '<div id="periodButtons" style="display: none; gap: 30px; justify-content: center; margin-bottom: 30px;">';
                html += '<button id="biweeklyBtn" style="padding: 12px 24px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: bold;">Biweekly for Last 3 Months</button>';
                html += '<button id="monthlyBtn" style="padding: 12px 24px; background: #1e3a5f; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: bold;">Last 6 Months</button>';
                html += '</div>';
                html += '<div id="chart"></div>';
                
                chartContainer.innerHTML = html;
                
                // Store selected user (single user selection)
                window.selectedUser = null;
                
                // Setup dropdown toggle functionality
                var billingBtn = document.getElementById('billingTeamBtn');
                var arBtn = document.getElementById('arTeamBtn');
                var billingDropdown = document.getElementById('billingDropdown');
                var arDropdown = document.getElementById('arDropdown');
                
                billingBtn.onclick = function(e) {
                    e.stopPropagation();
                    arDropdown.style.display = 'none';
                    billingDropdown.style.display = billingDropdown.style.display === 'none' ? 'block' : 'none';
                };
                
                arBtn.onclick = function(e) {
                    e.stopPropagation();
                    billingDropdown.style.display = 'none';
                    arDropdown.style.display = arDropdown.style.display === 'none' ? 'block' : 'none';
                };
                
                // Close dropdowns when clicking outside
                document.addEventListener('click', function(e) {
                    if (!billingBtn.contains(e.target) && !billingDropdown.contains(e.target)) {
                        billingDropdown.style.display = 'none';
                    }
                    if (!arBtn.contains(e.target) && !arDropdown.contains(e.target)) {
                        arDropdown.style.display = 'none';
                    }
                });
                
                // Handle member selection (single user)
                var dropdownItems = document.querySelectorAll('.dropdown-item');
                var periodButtons = document.getElementById('periodButtons');
                
                dropdownItems.forEach(function(item) {
                    item.onclick = function() {
                        var username = this.getAttribute('data-username');
                        billingDropdown.style.display = 'none';
                        arDropdown.style.display = 'none';
                        
                        // Clear previous selection
                        dropdownItems.forEach(function(i) {
                            i.style.backgroundColor = 'white';
                        });
                        
                        // Select this user
                        window.selectedUser = username;
                        this.style.backgroundColor = '#d4e6f1';
                        
                        // Show period buttons
                        var periodButtonsDiv = document.getElementById('periodButtons');
                        if (periodButtonsDiv) {
                            periodButtonsDiv.style.display = 'flex';
                        }
                    };
                    // Add hover effect
                    item.onmouseover = function() {
                        if (window.selectedUser !== this.getAttribute('data-username')) {
                            this.style.backgroundColor = '#f0f4f8';
                        }
                    };
                    item.onmouseout = function() {
                        if (window.selectedUser !== this.getAttribute('data-username')) {
                            this.style.backgroundColor = 'white';
                        }
                    };
                });
                
                // Setup button handlers
                document.getElementById('biweeklyBtn').onclick = function() {
                    if (!window.selectedUser) {
                        alert('Please select a user from the dropdowns');
                        return;
                    }
                    loadBiweeklyUserComparison(window.selectedUser);
                };
                
                document.getElementById('monthlyBtn').onclick = function() {
                    if (!window.selectedUser) {
                        alert('Please select a user from the dropdowns');
                        return;
                    }
                    loadMonthlyUserComparison(window.selectedUser);
                };
            }
            
            function loadBiweeklyUserComparison(username) {
                var chartDiv = document.getElementById('chart');
                
                // Show loading spinner
                chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading biweekly comparison data...</p></div>';
                
                // Fetch biweekly comparison data for selected user
                fetch('/biweekly-user-comparison-data?username=' + encodeURIComponent(username))
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderBiweeklyUserComparisonChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading biweekly comparison:', error);
                        chartDiv.innerHTML = '<p style="color: red;">Error loading biweekly comparison data</p>';
                    });
            }
            
            function loadMonthlyUserComparison(username) {
                var chartDiv = document.getElementById('chart');
                
                // Show loading spinner
                chartDiv.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading monthly comparison data...</p></div>';
                
                // Fetch monthly comparison data for selected user
                fetch('/monthly-user-comparison-data?username=' + encodeURIComponent(username))
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderMonthlyUserComparisonChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading monthly comparison:', error);
                        chartDiv.innerHTML = '<p style="color: red;">Error loading monthly comparison data</p>';
                    });
            }
            
            function renderBiweeklyUserComparisonChart(data) {
                var chartDiv = document.getElementById('chart');
                
                if (typeof Plotly === 'undefined') {
                    chartDiv.innerHTML = '<p style="color: red;">Plotly library not loaded. Please refresh the page.</p>';
                    return;
                }
                
                // Clear loading message
                chartDiv.innerHTML = '';
                
                var categories = data.categories || [];
                var periods = data.labels || [];
                var periodData = data.data || {};
                
                if (categories.length === 0 || periods.length === 0) {
                    chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for biweekly comparison.</p>';
                    return;
                }
                
                // Create abbreviated category names (first letter of each word) - same as denials comparison
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Convert counts from thousands to actual numbers for display (same format as denials comparison)
                var expandedPeriodData = {};
                periods.forEach(function(period) {
                    var counts = periodData[period] || [];
                    expandedPeriodData[period] = counts.map(function(count) {
                        return count * 1000; // Convert back from thousands
                    });
                });
                
                // Create traces for each period
                var traces = [];
                var colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b'];
                
                periods.forEach(function(period, index) {
                    var counts = expandedPeriodData[period] || [];
                    // Create text labels for count values on top of data points
                    var textLabels = counts.map(function(count) {
                        return count > 0 ? Math.round(count).toLocaleString() : '';
                    });
                    
                    traces.push({
                        x: abbreviatedCategories,
                        y: counts,
                        type: 'scatter',
                        mode: 'lines+markers+text',
                        name: period,
                        text: textLabels,
                        textposition: 'top',
                        textfont: {
                            size: 10,
                            color: colors[index % colors.length]
                        },
                        line: {
                            color: colors[index % colors.length],
                            width: 2
                        },
                        marker: {
                            size: 8,
                            color: colors[index % colors.length]
                        },
                        hovertemplate: '<b>%{fullData.name}</b><br>' +
                                       'Category: %{customdata}<br>' +
                                       'Count: %{y:,.0f}<extra></extra>',
                        customdata: categories
                    });
                });
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f', // Expanded thousands format (1,000, 2,000, etc.) - same as denials comparison
                        dtick: 1000, // Tick every 1000
                        showticklabels: true, // Show y-axis values
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)',
                        gridwidth: 1
                    },
                    xaxis: {
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)',
                        gridwidth: 1
                    },
                    height: 600,
                    width: null, // Auto width to fill container
                    autosize: true,
                    margin: { l: 80, r: 200, t: 50, b: 60 },
                    showlegend: true,
                    legend: {
                        x: 1.05,
                        y: 1,
                        xanchor: 'left',
                        yanchor: 'top',
                        font: {
                            size: 12,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        }
                    },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                Plotly.newPlot('chart', traces, layout, {responsive: true});
            }
            
            function renderMonthlyUserComparisonChart(data) {
                var chartDiv = document.getElementById('chart');
                
                if (typeof Plotly === 'undefined') {
                    chartDiv.innerHTML = '<p style="color: red;">Plotly library not loaded. Please refresh the page.</p>';
                    return;
                }
                
                // Clear loading message
                chartDiv.innerHTML = '';
                
                var categories = data.categories || [];
                var periods = data.labels || [];
                var periodData = data.data || {};
                
                if (categories.length === 0 || periods.length === 0) {
                    chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for monthly comparison.</p>';
                    return;
                }
                
                // Create abbreviated category names (first letter of each word) - same as denials comparison
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Convert counts from thousands to actual numbers for display (same format as denials comparison)
                var expandedPeriodData = {};
                periods.forEach(function(period) {
                    var counts = periodData[period] || [];
                    expandedPeriodData[period] = counts.map(function(count) {
                        return count * 1000; // Convert back from thousands
                    });
                });
                
                // Create traces for each period
                var traces = [];
                var colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b'];
                
                periods.forEach(function(period, index) {
                    var counts = expandedPeriodData[period] || [];
                    // Create text labels for count values on top of data points
                    var textLabels = counts.map(function(count) {
                        return count > 0 ? Math.round(count).toLocaleString() : '';
                    });
                    
                    traces.push({
                        x: abbreviatedCategories,
                        y: counts,
                        type: 'scatter',
                        mode: 'lines+markers+text',
                        name: period,
                        text: textLabels,
                        textposition: 'top',
                        textfont: {
                            size: 10,
                            color: colors[index % colors.length]
                        },
                        line: {
                            color: colors[index % colors.length],
                            width: 2
                        },
                        marker: {
                            size: 8,
                            color: colors[index % colors.length]
                        },
                        hovertemplate: '<b>%{fullData.name}</b><br>' +
                                       'Category: %{customdata}<br>' +
                                       'Count: %{y:,.0f}<extra></extra>',
                        customdata: categories
                    });
                });
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f', // Expanded thousands format (1,000, 2,000, etc.) - same as denials comparison
                        dtick: 1000, // Tick every 1000
                        showticklabels: true, // Show y-axis values
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)',
                        gridwidth: 1
                    },
                    xaxis: {
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)',
                        gridwidth: 1
                    },
                    height: 600,
                    width: null, // Auto width to fill container
                    autosize: true,
                    margin: { l: 80, r: 200, t: 50, b: 60 },
                    showlegend: true,
                    legend: {
                        x: 1.05,
                        y: 1,
                        xanchor: 'left',
                        yanchor: 'top',
                        font: {
                            size: 12,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        }
                    },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                Plotly.newPlot('chart', traces, layout, {responsive: true});
            }
            
            function renderDenialsBiweeklyComparisonChart(data) {
                var chartDiv = document.getElementById('chart');
                
                if (typeof Plotly === 'undefined') {
                    chartDiv.innerHTML = '<p style="color: red;">Plotly library not loaded. Please refresh the page.</p>';
                    return;
                }
                
                // Clear loading message
                chartDiv.innerHTML = '';
                
                var categories = data.categories || [];
                var periods = data.labels || [];
                var periodData = data.data || {};
                
                if (categories.length === 0 || periods.length === 0) {
                    chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for biweekly comparison.</p>';
                    return;
                }
                
                // Create abbreviated category names (first letter of each word)
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Convert counts from thousands to actual numbers for display
                var expandedPeriodData = {};
                periods.forEach(function(period) {
                    var counts = periodData[period] || [];
                    expandedPeriodData[period] = counts.map(function(count) {
                        return count * 1000; // Convert back from thousands
                    });
                });
                
                // Create traces for each period
                var traces = [];
                var colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b'];
                
                periods.forEach(function(period, index) {
                    var counts = expandedPeriodData[period] || [];
                    // Create text labels for count values on top of data points
                    var textLabels = counts.map(function(count) {
                        return count > 0 ? Math.round(count).toLocaleString() : '';
                    });
                    
                    traces.push({
                        x: abbreviatedCategories,
                        y: counts,
                        type: 'scatter',
                        mode: 'lines+markers+text',
                        name: period,
                        text: textLabels,
                        textposition: 'top',
                        textfont: {
                            size: 10,
                            color: colors[index % colors.length]
                        },
                        line: {
                            color: colors[index % colors.length],
                            width: 2
                        },
                        marker: {
                            size: 8,
                            color: colors[index % colors.length]
                        },
                        hovertemplate: '<b>%{fullData.name}</b><br>' +
                                       'Category: %{customdata}<br>' +
                                       'Count: %{y:,.0f}<extra></extra>',
                        customdata: categories
                    });
                });
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f',
                        dtick: 1000,
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                    },
                    height: 600,
                    width: null,
                    autosize: true,
                    margin: { l: 80, r: 200, t: 50, b: 60 },
                    showlegend: true,
                    legend: {
                        x: 1.05,
                        y: 1,
                        xanchor: 'left',
                        yanchor: 'top',
                        font: {
                            size: 12,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        }
                    },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                Plotly.newPlot('chart', traces, layout, {responsive: true});
            }
            
            function renderDenialsMonthlyComparisonChart(data) {
                var chartDiv = document.getElementById('chart');
                
                if (typeof Plotly === 'undefined') {
                    chartDiv.innerHTML = '<p style="color: red;">Plotly library not loaded. Please refresh the page.</p>';
                    return;
                }
                
                // Clear loading message
                chartDiv.innerHTML = '';
                
                var categories = data.categories || [];
                var periods = data.labels || [];
                var periodData = data.data || {};
                
                if (categories.length === 0 || periods.length === 0) {
                    chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for monthly comparison.</p>';
                    return;
                }
                
                // Create abbreviated category names (first letter of each word)
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Convert counts from thousands to actual numbers for display
                var expandedPeriodData = {};
                periods.forEach(function(period) {
                    var counts = periodData[period] || [];
                    expandedPeriodData[period] = counts.map(function(count) {
                        return count * 1000; // Convert back from thousands
                    });
                });
                
                // Create traces for each period
                var traces = [];
                var colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b'];
                
                periods.forEach(function(period, index) {
                    var counts = expandedPeriodData[period] || [];
                    // Create text labels for count values on top of data points
                    var textLabels = counts.map(function(count) {
                        return count > 0 ? Math.round(count).toLocaleString() : '';
                    });
                    
                    traces.push({
                        x: abbreviatedCategories,
                        y: counts,
                        type: 'scatter',
                        mode: 'lines+markers+text',
                        name: period,
                        text: textLabels,
                        textposition: 'top',
                        textfont: {
                            size: 10,
                            color: colors[index % colors.length]
                        },
                        line: {
                            color: colors[index % colors.length],
                            width: 2
                        },
                        marker: {
                            size: 8,
                            color: colors[index % colors.length]
                        },
                        hovertemplate: '<b>%{fullData.name}</b><br>' +
                                       'Category: %{customdata}<br>' +
                                       'Count: %{y:,.0f}<extra></extra>',
                        customdata: categories
                    });
                });
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f',
                        dtick: 1000,
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                    },
                    height: 600,
                    width: null,
                    autosize: true,
                    margin: { l: 80, r: 200, t: 50, b: 60 },
                    showlegend: true,
                    legend: {
                        x: 1.05,
                        y: 1,
                        xanchor: 'left',
                        yanchor: 'top',
                        font: {
                            size: 12,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        }
                    },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                Plotly.newPlot('chart', traces, layout, {responsive: true});
            }
            
            function loadClarificationGrouping() {
                // Remove active class from all submenu items and menu headers
                var items = document.querySelectorAll('.submenu-item, .menu-header');
                items.forEach(item => item.classList.remove('active'));
                // Add active class to clicked item
                event.target.classList.add('active');
                
                // Hide placeholder and show chart container
                document.getElementById('placeholder').style.display = 'none';
                var chartContainer = document.getElementById('chart-container');
                chartContainer.classList.add('active');
                
                // Show loading spinner
                chartContainer.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading clarification grouping data...</p></div>';
                
                // Fetch clarification grouping data
                fetch('/clarification-grouping-data')
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            chartContainer.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                        } else {
                            renderClarificationChart(data);
                        }
                    })
                    .catch(error => {
                        console.error('Error loading clarification grouping:', error);
                        chartContainer.innerHTML = '<p style="color: red;">Error loading clarification grouping data</p>';
                    });
            }
            
            
            function renderChart(data) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderChart(data);
                    }, 100);
                    return;
                }
                
                // Determine if this is for denials or rejections based on the active menu item
                var activeItem = document.querySelector('.submenu-item.active');
                var isRejection = activeItem && activeItem.textContent.trim() === 'Rejection';
                var chartTitle = isRejection ? 'Rejections Category Pie Chart' : 'Denials Category Pie Chart';
                var chartSubtitle = isRejection ? 'Click on a slice to view related rejection details' : 'Click on a slice to view related denial details';
                
                // Clear previous content and create chart HTML structure
                chartContainer.innerHTML = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">' + chartTitle + '</h2><p style="color: #2c5282; font-size: 16px; margin: 0;">' + chartSubtitle + '</p></div><div id="chart"></div><div id="popup"><div id="popup-header"><h3 id="popup-title"></h3><div id="popup-buttons"><button id="download">Download Excel</button><button id="close">Close</button></div></div><div id="popup-content"></div></div>';
                
                // Extract data
                var categories = data.categories;
                var counts = data.counts;
                var labelsWithCounts = data.labels_with_counts;
                var tableData = data.table_data;
                
                // Create chart data with distinct vibrant colors
                // Map specific colors to classifications
                var colorMap = {
                    "Inactive or Wrong policy Information": "#dd7e6b",
                    "Medicare paid more than Medicaid": "#f9cb9c",
                    "Incorrect/Invalid DOS": "#ffe599",
                    "TFL/Appeal time limit expired or not allowed": "#e1cfca",
                    "Missing or Invalid ICD/CPT code/Modifier/POS": "#a2c4c9",
                    "Provider enrollment issue": "#a4c2f4",
                    "Out of network": "#b4a7d6",
                    "Need additional information needed": "#d5a6bd",
                    "Non covered service": "#ea9999",
                    "Incorrect Billing": "#dbe098",
                    "Bundled service": "#bcc07b",
                    "Other": "#808080"
                };
                
                // Create color array based on classification order
                var vibrantColors = categories.map(function(cat) {
                    return colorMap[cat.trim()] || '#808080'; // Default gray if classification not in map
                });
                
                var chartData = [{
                    type: "pie",
                    labels: labelsWithCounts,  // These labels (with counts) will appear in the legend
                    values: counts,
                    textinfo: "label+percent",
                    hoverinfo: "label+value",
                    textposition: "outside",
                    automargin: true,
                    marker: { 
                        colors: vibrantColors,
                        line: { color: "#ffffff", width: 2 }
                    },
                    domain: { x: [0, 0.6], y: [0.3, 1] },
                    name: ""  // Empty name so legend shows the labels directly
                }];
                
                // Create layout with dark blue formal theme
                var layout = {
                    height: 700,
                    width: 1300,
                    margin: { l: 0, r: 0, t: 80, b: 0 },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: { 
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 14
                    },
                    showlegend: true,
                    legend: {
                        x: 0.75,
                        y: 1,
                        xanchor: "left",
                        yanchor: "top",
                        font: { 
                            size: 16,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        },
                        traceorder: "normal",
                        bgcolor: 'rgba(255,255,255,0.8)',
                        bordercolor: '#2c5282',
                        borderwidth: 1
                    }
                };
                
                // Render the chart
                Plotly.newPlot("chart", chartData, layout);
                
                // Setup popup functionality
                var popup = document.getElementById("popup");
                var popupContent = document.getElementById("popup-content");
                var popupTitle = document.getElementById("popup-title");
                var closeBtn = document.getElementById("close");
                var downloadBtn = document.getElementById("download");
                var currentCategory = "";
                
                // Function to download table as Excel
                function downloadTableAsExcel() {
    var table = popupContent.querySelector('table');
    if (!table) {
        alert('No table found to download');
        return;
    }

    var wb = XLSX.utils.book_new();
    var ws = XLSX.utils.table_to_sheet(table);

    // Convert ALL numbers and dates to strings, and left-align everything
    var range = XLSX.utils.decode_range(ws['!ref']);

    // Convert ALL cells to strings and left-align
    for (var R = 0; R <= range.e.r; ++R) {
        for (var C = range.s.c; C <= range.e.c; ++C) {
            var cellAddress = XLSX.utils.encode_cell({ r: R, c: C });

            if (!ws[cellAddress]) {
                ws[cellAddress] = {};
            }

            var cell = ws[cellAddress];

            if (cell && cell.v !== null && cell.v !== undefined) {

                // ✅ DATE FIX
                if (typeof cell.v === 'number' && cell.z && cell.z.toLowerCase().includes('d')) {
                    var d = XLSX.SSF.parse_date_code(cell.v);
                    cell.v =
                        String(d.m).padStart(2, '0') + '/' +
                        String(d.d).padStart(2, '0') + '/' +
                        d.y;
                } else {
                    cell.v = String(cell.v);
                }

                cell.t = 's'; // string type
                if (cell.z) delete cell.z;
            }

            // Initialize style for left alignment
            if (!cell.s) cell.s = {};
            if (!cell.s.alignment) cell.s.alignment = {};
            cell.s.alignment.horizontal = 'left';
            cell.s.alignment.vertical = 'top';
            cell.s.alignment.wrapText = false;
        }
    }

    if (!ws['!cols']) ws['!cols'] = [];

    for (var C = range.s.c; C <= range.e.c; ++C) {
        var maxWidth = 10;

        var headerCell = XLSX.utils.encode_cell({ r: 0, c: C });
        if (ws[headerCell] && ws[headerCell].v) {
            maxWidth = Math.max(maxWidth, String(ws[headerCell].v).length);
        }

        for (var R = 1; R <= range.e.r; ++R) {
            var cellAddress = XLSX.utils.encode_cell({ r: R, c: C });
            if (ws[cellAddress] && ws[cellAddress].v !== null && ws[cellAddress].v !== undefined) {
                maxWidth = Math.max(maxWidth, String(ws[cellAddress].v).length);
            }
        }

        ws['!cols'][C] = { wch: maxWidth + 3 };
    }

    XLSX.utils.book_append_sheet(wb, ws, "Data");

    var filename =
        currentCategory.replace(/[^a-z0-9]/gi, '_') + '_' +
        new Date().toISOString().split('T')[0] +
        '.xlsx';

    XLSX.writeFile(wb, filename);
}

                
                document.getElementById("chart").on('plotly_click', function(evt) {
                    var pointIndex = evt.points[0].pointNumber;
                    var category = categories[pointIndex];
                    currentCategory = category;
                    popupTitle.textContent = category;
                    
                    // Show popup with loading spinner
                    popup.style.display = "block";
                    popupContent.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading table data...</p></div>';
                    
                    // Load table data after a brief delay to show spinner
                    setTimeout(function() {
                        popupContent.innerHTML = tableData[category];
                    }, 300);
                });
                
                closeBtn.onclick = function() {
                    popup.style.display = "none";
                };
                
                downloadBtn.onclick = function() {
                    downloadTableAsExcel();
                };
            }
            
            function renderComparisonChart(data, period) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderComparisonChart(data, period);
                    }, 100);
                    return;
                }
                
                // Handle biweekly - now shows data
                // (no early return, let it process normally)
                
                // Get chart div and update title
                var chartDiv = document.getElementById('chart');
                var selectorDiv = chartContainer.querySelector('div[style*="text-align"]');
                    if (selectorDiv) {
                    // Update title with date
                    var titleElement = selectorDiv.querySelector('h2');
                    if (titleElement && data.title) {
                        titleElement.textContent = data.title;
                    }
                }
                
                if (!chartDiv) {
                        chartDiv = document.createElement('div');
                        chartDiv.id = 'chart';
                        chartContainer.appendChild(chartDiv);
                    } else {
                    chartDiv.innerHTML = '';
                }
                
                // Extract pie chart data
                var categories = data.categories || [];
                var counts = data.counts || [];
                var labelsWithCounts = data.labels_with_counts || [];
                var tableData = data.table_data || {};
                
                // Check if we have data to display
                if (!categories || categories.length === 0 || !counts || counts.length === 0) {
                    chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for the selected period.</p>';
                    return;
                }
                
                // Color mapping for classifications
                var colorMap = {
                    "Inactive or Wrong policy Information": "#dd7e6b",
                    "Medicare paid more than Medicaid": "#f9cb9c",
                    "Incorrect/Invalid DOS": "#ffe599",
                    "TFL/Appeal time limit expired or not allowed": "#e1cfca",
                    "Missing or Invalid ICD/CPT code/Modifier/POS": "#a2c4c9",
                    "Provider enrollment issue": "#a4c2f4",
                    "Out of network": "#b4a7d6",
                    "Need additional information needed": "#d5a6bd",
                    "Non covered service": "#ea9999",
                    "Incorrect Billing": "#dbe098",
                    "Bundled service": "#bcc07b",
                    "Other": "#808080"
                };
                
                // Create color array based on category order
                var vibrantColors = categories.map(function(cat) {
                    if (cat && typeof cat === 'string') {
                        return colorMap[cat.trim()] || '#808080';
                    }
                    return '#808080';
                });
                
                // Create pie chart data
                var chartData = [{
                    type: "pie",
                    labels: labelsWithCounts,
                    values: counts,
                    textinfo: "label+percent",
                    hoverinfo: "label+value",
                    textposition: "outside",
                    automargin: true,
                    marker: { 
                        colors: vibrantColors,
                        line: { color: "#ffffff", width: 2 }
                    },
                    domain: { x: [0, 0.6], y: [0.3, 1] },
                    name: ""
                }];
                
                // Create layout
                var layout = {
                    height: 700,
                    width: 1300,
                    margin: { l: 0, r: 0, t: 80, b: 0 },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: { 
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 14
                    },
                    showlegend: true,
                    legend: {
                        x: 0.75,
                        y: 1,
                        xanchor: "left",
                        yanchor: "top",
                        font: { 
                            size: 16,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        },
                        traceorder: "normal",
                        bgcolor: 'rgba(255,255,255,0.8)',
                        bordercolor: '#2c5282',
                        borderwidth: 1
                    }
                };
                
                // Render the chart
                Plotly.newPlot("chart", chartData, layout);
                
                // Setup popup functionality
                var popup = document.getElementById("popup");
                var popupContent = document.getElementById("popup-content");
                var popupTitle = document.getElementById("popup-title");
                var closeBtn = document.getElementById("close");
                var downloadBtn = document.getElementById("download");
                var currentCategory = "";
                
                // Function to download table as Excel
                function downloadTableAsExcel() {
                    var table = popupContent.querySelector('table');
                    if (!table) {
                        alert('No table found to download');
                        return;
                    }
                    
                    var wb = XLSX.utils.book_new();
                    var ws = XLSX.utils.table_to_sheet(table);
                    
                    // Get header row to identify date columns
                    var range = XLSX.utils.decode_range(ws['!ref']);
                    var dateColumnIndices = [];
                    for (var C = range.s.c; C <= range.e.c; ++C) {
                        var headerCell = XLSX.utils.encode_cell({r: 0, c: C});
                        if (ws[headerCell] && ws[headerCell].v) {
                            var headerText = String(ws[headerCell].v).toLowerCase();
                            if (headerText === 'dob' || headerText === 'dos' || headerText === 'denial date') {
                                dateColumnIndices.push(C);
                            }
                        }
                    }
                    
                    // Convert ALL numbers and dates to strings, and left-align everything
                    // Convert ALL cells to strings and left-align
                    for (var R = 0; R <= range.e.r; ++R) {
                    for (var C = range.s.c; C <= range.e.c; ++C) {
                            var cellAddress = XLSX.utils.encode_cell({r: R, c: C});
                            if (!ws[cellAddress]) {
                                ws[cellAddress] = {};
                            }
                            
                            var cell = ws[cellAddress];
                            if (cell && cell.v !== null && cell.v !== undefined) {
                                // For date columns, ensure mm/dd/yyyy format is preserved
                                if (dateColumnIndices.indexOf(C) !== -1 && R > 0) {
                                    // It's a date column data cell
                                    var dateValue = String(cell.v);
                                    // If it's already in mm/dd/yyyy format, keep it
                                    // If it's a date number, convert to mm/dd/yyyy
                                    if (typeof cell.v === 'number' && cell.z) {
                                        try {
                                            var d = XLSX.SSF.parse_date_code(cell.v);
                                            dateValue = String(d.m).padStart(2, '0') + '/' + String(d.d).padStart(2, '0') + '/' + d.y;
                                        } catch(e) {
                                            dateValue = String(cell.v);
                                        }
                                    }
                                    cell.v = dateValue;
                                } else {
                                    // Convert everything else to string
                                    cell.v = String(cell.v);
                                }
                                cell.t = 's'; // string type
                                // Remove any date format
                                if (cell.z) {
                                    delete cell.z;
                                }
                            }
                            
                            // Initialize style for left alignment
                            if (!cell.s) cell.s = {};
                            if (!cell.s.alignment) cell.s.alignment = {};
                            cell.s.alignment.horizontal = 'left';
                            cell.s.alignment.vertical = 'top';
                            cell.s.alignment.wrapText = false;
                        }
                    }
                    
                    if (!ws['!cols']) ws['!cols'] = [];
                    
                        for (var C = range.s.c; C <= range.e.c; ++C) {
                        var maxWidth = 10;
                        var headerCell = XLSX.utils.encode_cell({r: 0, c: C});
                        if (ws[headerCell] && ws[headerCell].v) {
                            maxWidth = Math.max(maxWidth, String(ws[headerCell].v).length);
                        }
                        for (var R = 1; R <= range.e.r; ++R) {
                            var cellAddress = XLSX.utils.encode_cell({r: R, c: C});
                            if (ws[cellAddress] && ws[cellAddress].v !== null && ws[cellAddress].v !== undefined) {
                                var cellValue = String(ws[cellAddress].v);
                                    maxWidth = Math.max(maxWidth, cellValue.length);
                                }
                            }
                        ws['!cols'][C] = { wch: maxWidth + 3 };
                    }
                    
                    XLSX.utils.book_append_sheet(wb, ws, "Data");
                    var filename = currentCategory.replace(/[^a-z0-9]/gi, '_') + '_' + new Date().toISOString().split('T')[0] + '.xlsx';
                    XLSX.writeFile(wb, filename);
                }
                
                // Click handler for pie chart slices
                document.getElementById("chart").on('plotly_click', function(evt) {
                    var pointIndex = evt.points[0].pointNumber;
                    var category = categories[pointIndex];
                    currentCategory = category;
                    popupTitle.textContent = category;
                    
                    // Show popup with loading spinner
                    popup.style.display = "block";
                    popupContent.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading table data...</p></div>';
                    
                    // Load table data after a brief delay to show spinner
                    setTimeout(function() {
                        popupContent.innerHTML = tableData[category] || '<p>No data available for this category</p>';
                    }, 300);
                });
                
                if (closeBtn) {
                    closeBtn.onclick = function() {
                        popup.style.display = "none";
                    };
                }
                
                if (downloadBtn) {
                    downloadBtn.onclick = function() {
                        downloadTableAsExcel();
                    };
                }
            }
            
            function renderDenialsComparisonChart(data) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderDenialsComparisonChart(data);
                    }, 100);
                    return;
                }
                
                // Check if we have data to display
                if (!data.categories || data.categories.length === 0) {
                    var chartDiv = document.getElementById('chart');
                    if (chartDiv) {
                        chartDiv.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for comparison.</p>';
                    } else {
                        chartContainer.innerHTML = '<p style="text-align: center; color: #2c5282; font-size: 16px; padding: 20px;">No data available for comparison.</p>';
                    }
                    return;
                }
                
                // Preserve buttons if they exist
                var buttonsDiv = chartContainer.querySelector('div[style*="display: flex"]');
                var headerDiv = chartContainer.querySelector('h2');
                
                // Get or create chart div
                var chartDiv = document.getElementById('chart');
                if (!chartDiv) {
                    chartDiv = document.createElement('div');
                    chartDiv.id = 'chart';
                    chartContainer.appendChild(chartDiv);
                }
                
                // Create hover tooltip div if it doesn't exist
                var hoverPopup = document.getElementById('category-popup');
                if (!hoverPopup) {
                    hoverPopup = document.createElement('div');
                    hoverPopup.id = 'category-popup';
                    hoverPopup.style.cssText = 'display: none; position: fixed; background: white; padding: 15px 20px; border: 1px solid #ccc; border-radius: 5px; box-shadow: 0 2px 8px rgba(0,0,0,0.2); z-index: 10000; pointer-events: none;';
                    hoverPopup.innerHTML = '<div id="category-full-name" style="color: black; font-size: 14px; font-weight: bold; margin: 0 0 5px 0;"></div><div id="current-month-count" style="color: black; font-size: 14px; margin: 0 0 3px 0;"></div><div id="previous-month-count" style="color: black; font-size: 14px; margin: 0;"></div>';
                    document.body.appendChild(hoverPopup);
                }
                
                // Clear only the chart div, preserve buttons
                chartDiv.innerHTML = '';
                
                // Extract data
                var categories = data.categories || [];
                var currentCounts = data.current_month_counts || [];
                var previousCounts = data.previous_month_counts || [];
                var tableData = data.table_data || {};
                var currentLabel = data.current_month_label || 'Current Month';
                var previousLabel = data.previous_month_label || 'Previous Month';
                
                // Create abbreviated category names (first letter of each word) - same as clarification
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Convert counts from thousands back to actual numbers for display (in expanded 1000s format)
                var currentCountsExpanded = currentCounts.map(function(count) {
                    return count * 1000; // Convert back from thousands
                });
                var previousCountsExpanded = previousCounts.map(function(count) {
                    return count * 1000; // Convert back from thousands
                });
                
                // Create text labels for count values on top of data points
                var currentTextLabels = currentCountsExpanded.map(function(count) {
                    return count > 0 ? Math.round(count).toLocaleString() : '';
                });
                var previousTextLabels = previousCountsExpanded.map(function(count) {
                    return count > 0 ? Math.round(count).toLocaleString() : '';
                });
                
                // Create traces for line chart with text labels
                var trace1 = {
                    x: abbreviatedCategories,
                    y: currentCountsExpanded,
                    type: 'scatter',
                    mode: 'lines+markers+text',
                    name: currentLabel,
                    text: currentTextLabels,
                    textposition: 'top',
                    textfont: {
                        size: 10,
                        color: '#FF0000'
                    },
                    line: {
                        color: '#FF0000', // Red for current month
                        width: 2
                    },
                    marker: {
                        size: 8,
                        color: '#FF0000'
                    },
                    hovertemplate: '<b>%{fullData.name}</b><br>' +
                                   'Category: %{customdata}<br>' +
                                   'Count: %{y:,.0f}<extra></extra>',
                    customdata: categories
                };
                
                var trace2 = {
                    x: abbreviatedCategories,
                    y: previousCountsExpanded,
                    type: 'scatter',
                    mode: 'lines+markers+text',
                    name: previousLabel,
                    text: previousTextLabels,
                    textposition: 'top',
                    textfont: {
                        size: 10,
                        color: '#0000FF'
                    },
                    line: {
                        color: '#0000FF', // Blue for previous month
                        width: 2
                    },
                    marker: {
                        size: 8,
                        color: '#0000FF'
                    },
                    hovertemplate: '<b>%{fullData.name}</b><br>' +
                                   'Category: %{customdata}<br>' +
                                   'Count: %{y:,.0f}<extra></extra>',
                    customdata: categories
                };
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f', // Expanded thousands format (1,000, 2,000, etc.)
                        dtick: 1000, // Tick every 1000
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                    },
                    height: 600,
                    width: null, // Auto width to fill container
                    autosize: true,
                    margin: { l: 80, r: 200, t: 50, b: 60 },
                    showlegend: true,
                    legend: {
                        x: 1.05,
                        y: 1,
                        xanchor: 'left',
                        yanchor: 'top',
                        font: {
                            size: 12,
                            color: '#1e3a5f',
                            family: 'Arial, sans-serif'
                        }
                    },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                // Render the line chart
                Plotly.newPlot("chart", [trace1, trace2], layout, {responsive: true});
                
                // Setup hover tooltip for points
                setTimeout(function() {
                    var chartDiv = document.getElementById('chart');
                    var hoverPopup = document.getElementById('category-popup');
                    var popupName = document.getElementById('category-full-name');
                    var popupCount = document.getElementById('category-count');
                    
                    if (chartDiv && hoverPopup && popupName) {
                        var currentMonthCountDiv = document.getElementById('current-month-count');
                        var previousMonthCountDiv = document.getElementById('previous-month-count');
                        
                        // Listen for hover events on the chart
                        chartDiv.on('plotly_hover', function(hoverData) {
                            if (hoverData && hoverData.points && hoverData.points.length > 0) {
                                var point = hoverData.points[0];
                                var pointIndex = point.pointNumber;
                                
                                if (pointIndex >= 0 && pointIndex < categories.length) {
                                    var fullCategoryName = categories[pointIndex];
                                    
                                    // Get counts for both months for this category
                                    var currentCount = currentCountsExpanded[pointIndex] || 0;
                                    var previousCount = previousCountsExpanded[pointIndex] || 0;
                                    
                                    // Update popup content
                                    popupName.textContent = fullCategoryName;
                                    currentMonthCountDiv.textContent = currentLabel + ' - ' + Math.round(currentCount).toLocaleString();
                                    previousMonthCountDiv.textContent = previousLabel + ' - ' + Math.round(previousCount).toLocaleString();
                                    
                                    // Position popup near cursor
                                    if (hoverData.event) {
                                        var x = hoverData.event.clientX;
                                        var y = hoverData.event.clientY;
                                        hoverPopup.style.left = (x + 10) + 'px';
                                        hoverPopup.style.top = (y - 10) + 'px';
                                    }
                                    hoverPopup.style.display = 'block';
                                }
                            }
                        });
                        
                        // Hide popup when mouse leaves
                        chartDiv.on('plotly_unhover', function() {
                            if (hoverPopup) {
                                hoverPopup.style.display = 'none';
                            }
                        });
                    }
                }, 500);
            }
            
            function renderEmailComparisonChart(data, type) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderEmailComparisonChart(data, type);
                    }, 100);
                    return;
                }
                
                // Capitalize first letter of type
                var typeLabel = type.charAt(0).toUpperCase() + type.slice(1);
                
                // Clear previous content and create chart HTML structure
                chartContainer.innerHTML = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">Email Comparison - ' + typeLabel + '</h2><p style="color: #2c5282; font-size: 16px; margin: 0;">Showing total ' + type + ' email counts</p></div><div id="chart"></div>';
                
                // Extract data and calculate total counts for each category
                var categories = ['A', 'B', 'C', 'D', 'E'];
                
                // Calculate total count for each category (sum across all periods)
                var categoryCounts = categories.map(function(cat) {
                    var values = data[cat] || [];
                    return values.reduce(function(sum, val) { return sum + (parseInt(val) || 0); }, 0);
                });
                
                // Color mapping for categories
                var colorMap = {
                    'A': '#FF0000', // Bright Red
                    'B': '#1e3a5f', // Dark Blue
                    'C': '#FF8000', // Orange
                    'D': '#FFFF00', // Yellow
                    'E': '#006400', // Dark Green
                };
                
                // Create bar chart trace
                var trace = {
                    x: categories,
                    y: categoryCounts,
                    type: 'bar',
                    marker: {
                        color: categories.map(function(cat) { return colorMap[cat]; }),
                        line: {
                            color: '#ffffff',
                            width: 1
                        }
                    },
                    text: categoryCounts,
                    textposition: 'outside',
                    textfont: {
                        size: 12,
                        color: '#1e3a5f'
                    }
                };
                
                var layout = {
                        xaxis: {
                        title: 'Category',
                            titlefont: {
                                size: 14,
                                color: '#1e3a5f'
                            },
                            tickfont: {
                                size: 12,
                                color: '#1e3a5f'
                            },
                        type: 'category'
                        },
                        yaxis: {
                            title: 'Count',
                            titlefont: {
                                size: 14,
                                color: '#1e3a5f'
                            },
                            tickfont: {
                                size: 12,
                                color: '#1e3a5f'
                            },
                            tickmode: 'linear',
                            tickformat: 'd',
                        dtick: 10,
                            showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                        },
                        height: 600,
                        width: 1000,
                        margin: { l: 80, r: 40, t: 20, b: 60 },
                    showlegend: false,
                        paper_bgcolor: 'rgba(0,0,0,0)',
                        plot_bgcolor: 'rgba(0,0,0,0)',
                        font: {
                            family: 'Arial, sans-serif',
                            color: '#1e3a5f',
                            size: 12
                        }
                    };
                
                // Render the bar chart
                Plotly.newPlot("chart", [trace], layout);
            }
            
            /*
            // COMMENTED OUT - Original clarification chart render functions
            function renderClarificationByAgingChart(data) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderClarificationByAgingChart(data);
                    }, 100);
                    return;
                }
                
                // Clear previous content and create chart HTML structure
                chartContainer.innerHTML = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">Clarification type by Aging</h2><p style="color: #2c5282; font-size: 16px; margin: 0;">Showing counts by category across time periods</p></div><div id="chart"></div>';
                
                // Extract data
                var categories = data.categories || [];
                var timePeriods = data.time_periods || ['0-6m', '6m-1y', '1-1.5y', '>1.5y'];
                    var seriesData = data.series || {};
                    
                // Color palette for categories
                var colors = ['#dd7e6b', '#f9cb9c', '#ffe599', '#b6d7a8', '#a2c4c9', '#a4c2f4', '#b4a7d6', '#d5a6bd', '#ea9999', '#808080'];
                
                // Create traces for each category
                var traces = categories.map(function(cat, idx) {
                    return {
                        x: timePeriods,
                        y: (seriesData[cat] || []).map(function(val) { return (val || 0) / 1000; }), // Convert to thousands
                            type: 'scatter',
                            mode: 'lines+markers',
                        name: cat,
                            line: {
                            width: 2,
                            color: colors[idx % colors.length]
                            },
                            marker: {
                                size: 8,
                            color: colors[idx % colors.length]
                            }
                    };
                    });
                    
                var layout = {
                        xaxis: {
                        title: 'Time Period',
                            titlefont: {
                                size: 14,
                                color: '#1e3a5f'
                            },
                            tickfont: {
                                size: 12,
                                color: '#1e3a5f'
                            },
                        type: 'category'
                        },
                        yaxis: {
                        title: 'Count (in thousands)',
                            titlefont: {
                                size: 14,
                                color: '#1e3a5f'
                            },
                            tickfont: {
                                size: 12,
                                color: '#1e3a5f'
                            },
                            tickmode: 'linear',
                        tickformat: ',.1f',
                            showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                        },
                        height: 600,
                        width: 1000,
                        margin: { l: 80, r: 40, t: 20, b: 60 },
                        showlegend: true,
                        legend: {
                            x: 1.05,
                            y: 1,
                            xanchor: 'left',
                            yanchor: 'top',
                            font: {
                                size: 12,
                                color: '#1e3a5f'
                            }
                        },
                        paper_bgcolor: 'rgba(0,0,0,0)',
                        plot_bgcolor: 'rgba(0,0,0,0)',
                        font: {
                            family: 'Arial, sans-serif',
                            color: '#1e3a5f',
                            size: 12
                        }
                    };
                
                // Render the line chart
                Plotly.newPlot("chart", traces, layout);
            }
            */
            
            function renderClarificationTypeChart(data) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderClarificationTypeChart(data);
                    }, 100);
                    return;
                }
                
                // Clear previous content and create chart HTML structure with hover tooltip
                chartContainer.innerHTML = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">Clarification Type</h2><p style="color: #2c5282; font-size: 16px; margin: 0;">Showing counts by category</p></div><div id="chart"></div><div id="category-popup" style="display: none; position: fixed; background: white; padding: 15px 20px; border: 1px solid #ccc; border-radius: 5px; box-shadow: 0 2px 8px rgba(0,0,0,0.2); z-index: 10000; pointer-events: none;"><div id="category-full-name" style="color: black; font-size: 14px; font-weight: bold; margin: 0 0 5px 0;"></div><div id="category-count" style="color: black; font-size: 14px; margin: 0;"></div></div>';
                
                // Extract data (same structure as clarification grouping)
                var categories = data.categories || [];
                var counts = data.counts || [];
                
                // Create abbreviated category names (first letter of each word) - same as clarification grouping
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Create mapping for legend (abbreviation -> full name)
                var categoryMapping = {};
                categories.forEach(function(cat, index) {
                    categoryMapping[abbreviatedCategories[index]] = cat;
                });
                
                // Create bar chart trace (bar chart instead of line chart since no time ranges)
                var trace = {
                    x: abbreviatedCategories,
                    y: counts,
                    type: 'bar',
                    marker: {
                        color: '#1e3a5f',
                        line: {
                            color: '#ffffff',
                            width: 1
                        }
                    },
                    text: counts,
                    textposition: 'outside',
                    textfont: {
                        size: 12,
                        color: '#1e3a5f'
                    },
                    hoverinfo: 'none'
                };
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f',
                        dtick: 1000,
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                    },
                    height: 600,
                    width: 1000,
                    margin: { l: 80, r: 40, t: 20, b: 60 },
                    showlegend: false,
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                // Render the bar chart
                Plotly.newPlot("chart", [trace], layout);
                
                // Setup hover tooltip for bars
                setTimeout(function() {
                    var chartDiv = document.getElementById('chart');
                    var popup = document.getElementById('category-popup');
                    var popupName = document.getElementById('category-full-name');
                    var popupCount = document.getElementById('category-count');
                    
                    if (chartDiv && popup && popupName && popupCount) {
                        // Listen for hover events on the chart
                        chartDiv.on('plotly_hover', function(hoverData) {
                            if (hoverData && hoverData.points && hoverData.points.length > 0) {
                                var point = hoverData.points[0];
                                var pointIndex = point.pointNumber;
                                if (pointIndex >= 0 && pointIndex < categories.length) {
                                    var fullCategoryName = categories[pointIndex];
                                    var count = counts[pointIndex];
                                    // Remove commas from count
                                    var countWithoutCommas = String(count).replace(/,/g, '');
                                    
                                    // Update popup content - category name first, then count below
                                    popupName.textContent = fullCategoryName;
                                    popupCount.textContent = countWithoutCommas;
                                    
                                    // Position popup near cursor
                                    if (hoverData.event) {
                                        var x = hoverData.event.clientX;
                                        var y = hoverData.event.clientY;
                                        popup.style.left = (x + 10) + 'px';
                                        popup.style.top = (y - 10) + 'px';
                                    }
                                    popup.style.display = 'block';
                                }
                            }
                        });
                        
                        // Hide popup when mouse leaves
                        chartDiv.on('plotly_unhover', function() {
                            if (popup) {
                                popup.style.display = 'none';
                            }
                        });
                    }
                }, 500);
            }
            
            function renderClarificationChart(data) {
                var chartContainer = document.getElementById('chart-container');
                
                // Wait for Plotly to be available
                if (typeof Plotly === 'undefined') {
                    setTimeout(function() {
                        renderClarificationChart(data);
                    }, 100);
                    return;
                }
                
                // Clear previous content and create chart HTML structure
                chartContainer.innerHTML = '<div style="text-align: center; margin-bottom: 20px;"><h2 style="color: #1e3a5f; font-size: 28px; margin-bottom: 10px; font-weight: 600;">Clarification by Time Range</h2><p style="color: #2c5282; font-size: 16px; margin: 0;">Showing counts for different time ranges</p></div><div id="chart"></div><div id="category-popup" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border: 2px solid #1e3a5f; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); z-index: 10000;"><div style="text-align: center;"><h3 style="color: #1e3a5f; margin: 0 0 10px 0;">Category Name</h3><p id="category-full-name" style="color: #2c5282; font-size: 16px; margin: 0 0 15px 0;"></p><button id="close-category-popup" style="padding: 8px 20px; background: #1e3a5f; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 14px;">Close</button></div></div>';
                
                // Extract data
                var categories = data.categories;
                var timeRanges = ['<0.6months', '0.6month-1yr', '1-1.5yr', '>1.5yr'];
                
                // Create abbreviated category names (first letter of each word)
                function getAbbreviation(categoryName) {
                    return categoryName.split(' ').map(function(word) {
                        return word.charAt(0).toUpperCase();
                    }).join('');
                }
                
                var abbreviatedCategories = categories.map(getAbbreviation);
                
                // Create mapping for legend (abbreviation -> full name)
                var categoryMapping = {};
                categories.forEach(function(cat, index) {
                    categoryMapping[abbreviatedCategories[index]] = cat;
                });
                
                // Color mapping for time ranges
                var rangeColors = {
                    '<0.6months': '#FF0000',      // Red
                    '0.6month-1yr': '#1e3a5f',    // Dark Blue
                    '1-1.5yr': '#FF8000',         // Orange
                    '>1.5yr': '#006400'           // Dark Green
                };
                
                // Create traces for each time range
                var traces = timeRanges.map(function(range) {
                    return {
                        x: abbreviatedCategories,
                        y: data[range] || [],
                        type: 'scatter',
                        mode: 'lines+markers',
                        name: range,
                        line: {
                            color: rangeColors[range],
                            width: 2
                        },
                        marker: {
                            size: 8,
                            color: rangeColors[range]
                        }
                    };
                });
                
                var layout = {
                    xaxis: {
                        title: 'Category',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        type: 'category'
                    },
                    yaxis: {
                        title: 'Count',
                        titlefont: {
                            size: 14,
                            color: '#1e3a5f'
                        },
                        tickfont: {
                            size: 12,
                            color: '#1e3a5f'
                        },
                        tickmode: 'linear',
                        tickformat: ',.0f',
                        dtick: 1000,
                        showgrid: true,
                        gridcolor: 'rgba(128, 128, 128, 0.2)'
                    },
                    height: 600,
                    width: 1000,
                    margin: { l: 80, r: 40, t: 20, b: 60 },
                    showlegend: true,
                    legend: {
                        x: 1.05,
                        y: 1,
                        xanchor: 'left',
                        yanchor: 'top',
                        font: {
                            size: 12,
                            color: '#1e3a5f'
                        }
                    },
                    paper_bgcolor: 'rgba(0,0,0,0)',
                    plot_bgcolor: 'rgba(0,0,0,0)',
                    font: {
                        family: 'Arial, sans-serif',
                        color: '#1e3a5f',
                        size: 12
                    }
                };
                
                // Render the line chart
                Plotly.newPlot("chart", traces, layout);
                
                // Setup close button for category popup
                var closeCategoryPopupBtn = document.getElementById('close-category-popup');
                if (closeCategoryPopupBtn) {
                    closeCategoryPopupBtn.onclick = function() {
                        document.getElementById('category-popup').style.display = 'none';
                    };
                }
                
                // Add click handler for x-axis labels to show popup with full category name
                setTimeout(function() {
                    var chartDiv = document.getElementById('chart');
                    if (chartDiv) {
                        // Listen for click events on the chart
                        chartDiv.on('plotly_click', function(data) {
                            if (data && data.points && data.points.length > 0) {
                                var pointIndex = data.points[0].pointNumber;
                                if (pointIndex >= 0 && pointIndex < categories.length) {
                                    var fullCategoryName = categories[pointIndex];
                                    var popup = document.getElementById('category-popup');
                                    var popupText = document.getElementById('category-full-name');
                                    if (popup && popupText) {
                                        popupText.textContent = fullCategoryName;
                                        popup.style.display = 'block';
                                    }
                                }
                            }
                        });
                        
                        // Also add click handler for x-axis tick labels
                        var xAxisLabels = chartDiv.querySelectorAll('.xtick text');
                        xAxisLabels.forEach(function(label, index) {
                            if (index < abbreviatedCategories.length) {
                                label.style.cursor = 'pointer';
                                label.onclick = function(e) {
                                    e.stopPropagation();
                                    var fullCategoryName = categories[index];
                                    var popup = document.getElementById('category-popup');
                                    var popupText = document.getElementById('category-full-name');
                                    if (popup && popupText) {
                                        popupText.textContent = fullCategoryName;
                                        popup.style.display = 'block';
                                    }
                                };
                            }
                        });
                    }
                }, 500);
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/logout")
async def logout(request: Request):
    """Logout and clear session"""
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

@app.post("/logout")
async def logout_post(request: Request):
    """Logout and clear session (POST method)"""
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

def get_chart_data():
    """Get chart data from CSV file and map categories to classifications for pie chart"""
    df = get_denials_dataframe()
    
    # Define classification map
    classification_map = {
        "Different insurance as primary": "Inactive or Wrong policy Information",
        "No active coverage": "Inactive or Wrong policy Information",
        "Wrong insurance": "Inactive or Wrong policy Information",
        "Wrong patient info": "Inactive or Wrong policy Information",
        "Wrong policy information": "Inactive or Wrong policy Information",
        "Prior to coverage": "Inactive or Wrong policy Information",
        "Missing/wrong Claim information": "Inactive or Wrong policy Information",
        "Covered under HMO Plan": "Inactive or Wrong policy Information",
        "Patient ineligible for this service": "Inactive or Wrong policy Information",
        "MCR paid more than MCD allowed amt": "Medicare paid more than Medicaid",
        "Medicare paid more than Medicaid": "Medicare paid more than Medicaid",
        "Primary paid more than sec allowed amount": "Medicare paid more than Medicaid",
        "Invalid DOS": "Incorrect/Invalid DOS",
        "Incorrect DOS": "Incorrect/Invalid DOS",
        "Timely filing limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal time limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal Not Allowed": "TFL/Appeal time limit expired or not allowed",
        "Appeal allowed": "TFL/Appeal time limit expired or not allowed",
        "Invalid CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing main CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong/Incorrect ICD Code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with DX.code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong POS": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Invalid number of units": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with provider speciality": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing Modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "EFT enrollment pending": "Provider enrollment issue",
        "Provider not eligible": "Provider enrollment issue",
        "Provider not enrolled": "Provider enrollment issue",
        "No Medicare credentialing": "Provider enrollment issue",
        "No Medicaid credentialing": "Provider enrollment issue",
        "Missing/invalid NPI of Billing provider in field 33a.": "Provider enrollment issue",
        "Missing/invalid NPI of Rendering Provider in field 24J.": "Provider enrollment issue",
        "Missing/invalid reffering Provider info": "Provider enrollment issue",
        "Out of Network": "Out of network",
        "Provider Out of Network": "Out of network",
        "no authorization": "Out of network",
        "Missing prior authorization": "Out of network",
        "Missing referral information": "Out of network",
        "Missing medical record": "Need additional information needed",
        "COB missing": "Need additional information needed",
        "Missing NDC code": "Need additional information needed",
        "Missing documentation": "Need additional information needed",
        "Missing EOB": "Need additional information needed",
        "Need Add-on-code": "Need additional information needed",
        "Need W9 form": "Need additional information needed",
        "Accident Info required": "Need additional information needed",
        "Missing illness information": "Need additional information needed",
        "No Medical Necessity": "Need additional information needed",
        "Pre-existing condition": "Need additional information needed",
        "Itemized bill needed": "Need additional information needed",
        "Clinical Review Determination": "Need additional information needed",
        "Non covered service": "Non covered service",
        "non covered submitted via paper": "Non covered service",
        "Charges too high": "Other",
        "Claim previously paid": "Other",
        "Contractual obligation": "Other",
        "Date of death precedes DOS": "Other",
        "Duplicate claim": "Other",
        "Exceeds clinical guidelines": "Other",
        "Invalid redetermination": "Other",
        "Managed care withholding": "Other",
        "Not met residency requirement": "Other",
        "Other": "Other",
        "Participating Provider Discount": "Other",
        "Patient in Hospice": "Other",
        "Patient incarcerated": "Other",
        "Payment made to another provider": "Other",
        "The qualifying service has not been received": "Other",
        "Claim Adjustment Due to Resubmission": "Incorrect Billing",
        "Incorrect Patient Billing": "Incorrect Billing",
        "Corrected Claim": "Incorrect Billing",
        "Resubmit the claim": "Incorrect Billing",
        "Invalid Taxpayer ID": "Incorrect Billing",
        "Revised claim with new claim number": "Incorrect Billing",
        "Invalid discharge date": "Incorrect Billing",
        "Charges exceeded, maximum allowed": "Incorrect Billing",
        "Negotiated discount": "Bundled service",
        "Benefit limited": "Bundled service",
        "Incidental Service": "Bundled service",
        "Max benefit exceeded": "Bundled service"
    }

    # Map CATEGORY to classification
    df['CLASSIFICATION'] = df['CATEGORY'].map(classification_map).fillna('Other')

    # Group by classification for pie chart
    df_grouped = df.groupby("CLASSIFICATION", as_index=False).size().rename(columns={"size": "count"})

    # Prepare HTML tables per CLASSIFICATION (for popup)
    table_data = {}
    for cls in df["CLASSIFICATION"].unique():
        # Include Category column and ROLE_ID, sort by Clinic name alphabetically
        subset = df[df["CLASSIFICATION"] == cls][["Clinic","Pt Name","MRN","DOB","DOS","Payer", "CPT", "Reason", "CATEGORY", "Denial Date", "User", "ROLE_ID"]].copy()
        
        # Sort by Clinic name alphabetically
        subset = subset.sort_values(by="Clinic", ascending=True)
        
        # Create Biller Role Type column based on ROLE_ID
        def get_biller_role_type(role_id):
            if pd.isna(role_id):
                return ''
            try:
                role_id_int = int(role_id)
                if role_id_int == 6:
                    return 'Biller'
                elif role_id_int == 14:
                    return 'AR Biller'
                else:
                    return ''
            except (ValueError, TypeError):
                return ''
        
        subset['Biller Role Type'] = subset['ROLE_ID'].apply(get_biller_role_type)
        
        # Rename CATEGORY to Category for display
        subset.rename(columns={"CATEGORY": "Category"}, inplace=True)
        
        # Select final columns including Biller Role Type
        subset = subset[["Clinic","Pt Name","MRN","DOB","DOS","Payer", "CPT", "Reason", "Category", "Denial Date", "User", "Biller Role Type"]]
        
        # Format date columns to mm/dd/yyyy
        date_columns = ["DOB", "DOS", "Denial Date"]
        for col in date_columns:
            if col in subset.columns:
                # Convert to datetime if not already, handling errors
                subset[col] = pd.to_datetime(subset[col], errors='coerce')
                # Format to mm/dd/yyyy, replacing NaT with empty string
                subset[col] = subset[col].dt.strftime('%m/%d/%Y').fillna('')
        
        table_data[cls] = subset.to_html(index=False, border=1)

    # Create labels with counts in brackets for legend
    labels_with_counts = [f"{cat} ({count})" for cat, count in zip(df_grouped["CLASSIFICATION"], df_grouped["count"])]

    # Serialize data safely for embedding into JS
    js_categories = json.dumps(list(df_grouped["CLASSIFICATION"]))
    js_counts = json.dumps(list(df_grouped["count"]))
    js_labels_with_counts = json.dumps(labels_with_counts)
    js_table_data = json.dumps(table_data)

    return js_categories, js_counts, js_labels_with_counts, js_table_data


@app.get("/button-data")
def button_data(request: Request):
    """API endpoint to get denial chart data as JSON"""
    # Check if user is authenticated
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    
    try:
        js_categories, js_counts, js_labels_with_counts, js_table_data = get_chart_data()
        
        # Return just the data, not HTML with scripts
        return JSONResponse(content={
            "categories": json.loads(js_categories),
            "counts": json.loads(js_counts),
            "labels_with_counts": json.loads(js_labels_with_counts),
            "table_data": json.loads(js_table_data)
        })
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

@app.get("/button", response_class=HTMLResponse)
def button(request: Request):
    """Interactive denials chart from CSV file"""
    # Check if user is authenticated
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    
    try:
        js_categories, js_counts, js_labels_with_counts, js_table_data = get_chart_data()
        
        html = f"""
        <html>
        <head>
            <title>Interactive Denials Chart</title>
            <script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f8f9fa;
                    text-align: center;
                    margin: 1px;
                }}
                #chart {{
                    width: 700px;
                    margin-left: 0;
                    text-align: left;
                    margin-top:-20px;
                }}
                #popup {{
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: white;
                    z-index: 1000;
                    overflow: hidden;
                }}
                #popup-header {{
                    position: sticky;
                    top: 0;
                    background: white;
                    padding: 15px 20px;
                    border-bottom: 2px solid #2c5282;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    z-index: 1001;
                    box-shadow: 0px 2px 5px rgba(0,0,0,0.1);
                }}
                #popup-header h3 {{
                    margin: 0;
                    color: #1e3a5f;
                    font-size: 24px;
                }}
                #popup-buttons {{
                    display: flex;
                    gap: 10px;
                }}
                #close, #download {{
                    background-color: #ff4d4d;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 14px;
                    font-weight: bold;
                    transition: background-color 0.3s;
                }}
                #close:hover {{
                    background-color: #ff3333;
                }}
                #download {{
                    background-color: #28a745;
                }}
                #download:hover {{
                    background-color: #218838;
                }}
                #popup-content {{
                    padding: 20px;
                    overflow-y: auto;
                    height: calc(100% - 80px);
                }}
                table {{
                    margin-top: 10px;
                    border-collapse: collapse;
                    width: 100%;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                    text-align: left;
                }}
                .loading-spinner {{
                    display: inline-block;
                    width: 40px;
                    height: 40px;
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #1e3a5f;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
                .loading-container {{
                    text-align: center;
                    padding: 40px;
                }}
                .loading-container p {{
                    color: #2c5282;
                    font-size: 16px;
                    margin-top: 15px;
                }}
            </style>
        </head>
        <body>
            <h2>Denials Category Pie Chart</h2>
            <p>Click on a slice to view related denial details.</p>
            <div id="chart"></div>

            <div id="popup">
                <div id="popup-header">
                    <h3 id="popup-title"></h3>
                    <div id="popup-buttons">
                        <button id="download">Download Excel</button>
                        <button id="close">Close</button>
                    </div>
                </div>
                <div id="popup-content"></div>
            </div>

            <script>
                var categories = {js_categories};
                var counts = {js_counts};
                var labelsWithCounts = {js_labels_with_counts};
                var tableData = {js_table_data};

                var data = [{{
                    type: "pie",
                    labels: labelsWithCounts,
                    values: counts,
                    textinfo: "label+percent",
                    hoverinfo: "label+value",
                    textposition: "outside",
                    automargin: true,
                    marker: {{ line: {{ color: "white", width: 2 }} }},
                    domain: {{ x: [0, 0.6], y: [0.3, 1] }}
                }}];

                var layout = {{
                    height: 400,
                    width: 1000,
                    margin: {{ l: 0, r: 0, t: 80, b: 0 }},
                    showlegend: true,
                    legend: {{
                        x: 1.05,
                        y: 1,
                        xanchor: "left",
                        yanchor: "top",
                        font: {{ size: 12 }}
                    }}
                }};

                Plotly.newPlot("chart", data, layout);

                var popup = document.getElementById("popup");
                var popupContent = document.getElementById("popup-content");
                var popupTitle = document.getElementById("popup-title");
                var closeBtn = document.getElementById("close");
                var downloadBtn = document.getElementById("download");
                var currentCategory = "";

                // Function to download table as Excel
                function downloadTableAsExcel() {{
                    var table = popupContent.querySelector('table');
                    if (!table) {{
                        alert('No table found to download');
                        return;
                    }}
                    
                    // Convert HTML table to worksheet
                    var wb = XLSX.utils.book_new();
                    var ws = XLSX.utils.table_to_sheet(table);
                    
                    // Convert ALL numbers and dates to strings, and left-align everything
                    var range = XLSX.utils.decode_range(ws['!ref']);
                    for (var R = 0; R <= range.e.r; ++R) {{
                    for (var C = range.s.c; C <= range.e.c; ++C) {{
                            var cellAddress = XLSX.utils.encode_cell({{r: R, c: C}});
                            if (!ws[cellAddress]) {{
                                ws[cellAddress] = {{}};
                            }}
                            
                            var cell = ws[cellAddress];
                            if (cell && cell.v !== null && cell.v !== undefined) {{
                                // Convert everything to string
                                cell.v = String(cell.v);
                                cell.t = 's'; // string type
                                // Remove any date format
                                if (cell.z) {{
                                    delete cell.z;
                                }}
                            }}
                            
                            // Initialize style for left alignment
                            if (!cell.s) cell.s = {{}};
                            if (!cell.s.alignment) cell.s.alignment = {{}};
                            cell.s.alignment.horizontal = 'left';
                            cell.s.alignment.vertical = 'top';
                            cell.s.alignment.wrapText = false;
                        }}
                    }}
                    
                    if (!ws['!cols']) ws['!cols'] = [];
                    
                    // Calculate and set column widths for all columns to show full data
                    for (var C = range.s.c; C <= range.e.c; ++C) {{
                        var maxWidth = 10; // Minimum width
                        // Check header width
                        var headerCell = XLSX.utils.encode_cell({{r: 0, c: C}});
                        if (ws[headerCell] && ws[headerCell].v) {{
                            maxWidth = Math.max(maxWidth, String(ws[headerCell].v).length);
                        }}
                        // Check data widths - iterate through all rows
                        for (var R = 1; R <= range.e.r; ++R) {{
                            var cellAddress = XLSX.utils.encode_cell({{r: R, c: C}});
                            if (ws[cellAddress] && ws[cellAddress].v !== null && ws[cellAddress].v !== undefined) {{
                                var cellValue = String(ws[cellAddress].v);
                                    maxWidth = Math.max(maxWidth, cellValue.length);
                            }}
                        }}
                        // Set width with padding to ensure full visibility (no cap)
                        ws['!cols'][C] = {{ wch: maxWidth + 3 }};
                    }}
                    
                    XLSX.utils.book_append_sheet(wb, ws, "Data");
                    
                    // Generate filename with category name and current date
                    var filename = currentCategory.replace(/[^a-z0-9]/gi, '_') + '_' + new Date().toISOString().split('T')[0] + '.xlsx';
                    
                    // Download the file
                    XLSX.writeFile(wb, filename);
                }}

                document.getElementById("chart").on('plotly_click', function(evt) {{
                    var pointIndex = evt.points[0].pointNumber;
                    var category = categories[pointIndex];
                    currentCategory = category;
                    popupTitle.textContent = category;
                    
                    // Show popup with loading spinner
                    popup.style.display = "block";
                    popupContent.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div><p>Loading table data...</p></div>';
                    
                    // Load table data after a brief delay to show spinner
                    setTimeout(function() {{
                        popupContent.innerHTML = tableData[category];
                    }}, 300);
                }});

                closeBtn.onclick = function() {{
                    popup.style.display = "none";
                }};

                downloadBtn.onclick = function() {{
                    downloadTableAsExcel();
                }};
            </script>
        </body>
        </html>
        """
        return HTMLResponse(content=html)
    except Exception as e:
        import traceback
        return HTMLResponse(content=f"<h3>Error in /button:</h3><pre>{traceback.format_exc()}</pre>")

# --------------------------------------------------------------------
# Comparison endpoint
def get_comparison_data_by_period(period, date=None, week_end=None):
    df = get_denials_dataframe()

    classification_map = {
        "Different insurance as primary": "Inactive or Wrong policy Information",
        "No active coverage": "Inactive or Wrong policy Information",
        "Wrong insurance": "Inactive or Wrong policy Information",
        "Wrong patient info": "Inactive or Wrong policy Information",
        "Wrong policy information": "Inactive or Wrong policy Information",
        "Prior to coverage": "Inactive or Wrong policy Information",
        "Missing/wrong Claim information": "Inactive or Wrong policy Information",
        "Covered under HMO Plan": "Inactive or Wrong policy Information",
        "Patient ineligible for this service": "Inactive or Wrong policy Information",
        "MCR paid more than MCD allowed amt": "Medicare paid more than Medicaid",
        "Medicare paid more than Medicaid": "Medicare paid more than Medicaid",
        "Primary paid more than sec allowed amount": "Medicare paid more than Medicaid",
        "Invalid DOS": "Incorrect/Invalid DOS",
        "Incorrect DOS": "Incorrect/Invalid DOS",
        "Timely filing limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal time limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal Not Allowed": "TFL/Appeal time limit expired or not allowed",
        "Appeal allowed": "TFL/Appeal time limit expired or not allowed",
        "Invalid CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing main CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong/Incorrect ICD Code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with DX.code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong POS": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Invalid number of units": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with provider speciality": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing Modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "EFT enrollment pending": "Provider enrollment issue",
        "Provider not eligible": "Provider enrollment issue",
        "Provider not enrolled": "Provider enrollment issue",
        "No Medicare credentialing": "Provider enrollment issue",
        "No Medicaid credentialing": "Provider enrollment issue",
        "Missing/invalid NPI of Billing provider in field 33a.": "Provider enrollment issue",
        "Missing/invalid NPI of Rendering Provider in field 24J.": "Provider enrollment issue",
        "Missing/invalid reffering Provider info": "Provider enrollment issue",
        "Out of Network": "Out of network",
        "Provider Out of Network": "Out of network",
        "no authorization": "Out of network",
        "Missing prior authorization": "Out of network",
        "Missing referral information": "Out of network",
        "Missing medical record": "Need additional information needed",
        "COB missing": "Need additional information needed",
        "Missing NDC code": "Need additional information needed",
        "Missing documentation": "Need additional information needed",
        "Missing EOB": "Need additional information needed",
        "Need Add-on-code": "Need additional information needed",
        "Need W9 form": "Need additional information needed",
        "Accident Info required": "Need additional information needed",
        "Missing illness information": "Need additional information needed",
        "No Medical Necessity": "Need additional information needed",
        "Pre-existing condition": "Need additional information needed",
        "Itemized bill needed": "Need additional information needed",
        "Clinical Review Determination": "Need additional information needed",
        "Non covered service": "Non covered service",
        "non covered submitted via paper": "Non covered service",
        "Charges too high": "Other",
        "Claim previously paid": "Other",
        "Contractual obligation": "Other",
        "Date of death precedes DOS": "Other",
        "Duplicate claim": "Other",
        "Exceeds clinical guidelines": "Other",
        "Invalid redetermination": "Other",
        "Managed care withholding": "Other",
        "Not met residency requirement": "Other",
        "Other": "Other",
        "Participating Provider Discount": "Other",
        "Patient in Hospice": "Other",
        "Patient incarcerated": "Other",
        "Payment made to another provider": "Other",
        "The qualifying service has not been received": "Other",
        "Claim Adjustment Due to Resubmission": "Incorrect Billing",
        "Incorrect Patient Billing": "Incorrect Billing",
        "Corrected Claim": "Incorrect Billing",
        "Resubmit the claim": "Incorrect Billing",
        "Invalid Taxpayer ID": "Incorrect Billing",
        "Revised claim with new claim number": "Incorrect Billing",
        "Invalid discharge date": "Incorrect Billing",
        "Charges exceeded, maximum allowed": "Incorrect Billing",
        "Negotiated discount": "Bundled service",
        "Benefit limited": "Bundled service",
        "Incidental Service": "Bundled service",
        "Max benefit exceeded": "Bundled service"
    }

    df['CLASSIFICATION'] = df['CATEGORY'].map(classification_map).fillna('Other')
    df['Denial Date'] = pd.to_datetime(df['Denial Date'].astype(str).str.strip(), errors='coerce')

    df = df.dropna(subset=['Denial Date'])

    # ============================
    # DAILY - Yesterday's data
    # ============================
    if period == "daily":
        # Get current date and calculate yesterday
        current_date = pd.Timestamp.now()
        # Get yesterday's date
        yesterday = current_date - pd.Timedelta(days=1)
        yesterday_date = yesterday.date()
        
        # Filter to yesterday's data
        df['Denial Date Date'] = df['Denial Date'].dt.date
        df = df[df['Denial Date Date'] == yesterday_date]
        
        # Group by classification for pie chart
        df_grouped = df.groupby("CLASSIFICATION", as_index=False).size().rename(columns={"size": "count"})
        
        # Prepare HTML tables per CLASSIFICATION (for popup) - include Category and Biller Role Type
        table_data = {}
        # Include these columns: Clinic, MRN, DOS, Payer, CPT, Reason, CATEGORY, Denial Date, User, ROLE_ID
        columns_to_include = ['Clinic', 'MRN', 'DOS', 'Payer', 'CPT', 'Reason', 'CATEGORY', 'Denial Date', 'User', 'ROLE_ID']
        # Ensure DOS and Denial Date are always in the list if they exist in df
        if 'DOS' in df.columns and 'DOS' not in columns_to_include:
            columns_to_include.append('DOS')
        if 'Denial Date' in df.columns and 'Denial Date' not in columns_to_include:
            columns_to_include.append('Denial Date')
        available_columns = [col for col in columns_to_include if col in df.columns]
        
        for cls in df["CLASSIFICATION"].unique():
            subset = df[df["CLASSIFICATION"] == cls][available_columns].copy()
            
            # Sort by Clinic name alphabetically
            subset = subset.sort_values(by="Clinic", ascending=True)
            
            # Create Biller Role Type column based on ROLE_ID
            def get_biller_role_type(role_id):
                if pd.isna(role_id):
                    return ''
                try:
                    role_id_int = int(role_id)
                    if role_id_int == 6:
                        return 'Biller'
                    elif role_id_int == 14:
                        return 'AR Biller'
                    else:
                        return ''
                except (ValueError, TypeError):
                    return ''
            
            # Always create Biller Role Type column (even if ROLE_ID is missing, it will be empty)
            if 'ROLE_ID' in subset.columns:
                subset['Biller Role Type'] = subset['ROLE_ID'].apply(get_biller_role_type)
            else:
                # If ROLE_ID column doesn't exist, create empty Biller Role Type column
                subset['Biller Role Type'] = ''
            
            # Rename CATEGORY to Category for display
            if 'CATEGORY' in subset.columns:
                subset.rename(columns={"CATEGORY": "Category"}, inplace=True)
            
            # Ensure all expected columns exist, even if empty
            for col in available_columns:
                if col not in subset.columns:
                    subset[col] = ''
            
            # Reorder to match expected column order (with Category and Biller Role Type)
            display_columns = ['Clinic', 'MRN', 'DOB', 'DOS', 'Payer', 'CPT', 'Reason', 'Category', 'Denial Date', 'User', 'Biller Role Type']
            display_columns = [col for col in display_columns if col in subset.columns]
            subset = subset[display_columns]
            
            # Format date columns to mm/dd/yyyy
            date_columns = ["DOB", "DOS", "Denial Date"]
            for col in date_columns:
                if col in subset.columns:
                    subset[col] = pd.to_datetime(subset[col], errors='coerce')
                    subset[col] = subset[col].dt.strftime('%m/%d/%Y').fillna('')
            
            table_data[cls] = subset.to_html(index=False, border=1)
        
        # Create labels with counts in brackets for legend
        labels_with_counts = [f"{cat} ({count})" for cat, count in zip(df_grouped["CLASSIFICATION"], df_grouped["count"])]
        
        # Format title
        title = f"Denial Status on {yesterday.strftime('%d %B %Y')}"
        
        return {
            "categories": list(df_grouped["CLASSIFICATION"]),
            "counts": list(df_grouped["count"]),
            "labels_with_counts": labels_with_counts,
            "table_data": table_data,
            "title": title
        }

    # ============================
    # BIWEEKLY - Show data for previous category period
    # ============================
    elif period == "biweekly":
        # Get current date
        today = pd.Timestamp.now()
        current_day = today.day
        current_month = today.month
        current_year = today.year
        
        # Determine which category current date belongs to
        if current_day <= 15:
            # Current date is in category 1 (1-15), so show previous category 2 (16-end of previous month)
            # Get previous month
            if current_month == 1:
                prev_month = 12
                prev_year = current_year - 1
            else:
                prev_month = current_month - 1
                prev_year = current_year
            
            # Determine days in previous month
            if prev_month in [1, 3, 5, 7, 8, 10, 12]:  # 31-day months
                days_in_prev_month = 31
            elif prev_month in [4, 6, 9, 11]:  # 30-day months
                days_in_prev_month = 30
            else:  # February
                # Check if leap year
                if (prev_year % 4 == 0 and prev_year % 100 != 0) or (prev_year % 400 == 0):
                    days_in_prev_month = 29
                else:
                    days_in_prev_month = 28
            
            start_day = 16
            end_day = days_in_prev_month
            category_range = f"16-{days_in_prev_month}"
            target_month = prev_month
            target_year = prev_year
        else:
            # Current date is in category 2 (16-end), so show previous category 1 (1-15 of current month)
            start_day = 1
            end_day = 15
            category_range = "1-15"
            target_month = current_month
            target_year = current_year
        
        # Filter to the previous category's date range
        df['Denial Date Date'] = df['Denial Date'].dt.date
        df['Denial Date Year'] = df['Denial Date'].dt.year
        df['Denial Date Month'] = df['Denial Date'].dt.month
        df['Denial Date Day'] = df['Denial Date'].dt.day
        
        # Filter to target month and the selected category range
        df = df[
            (df['Denial Date Year'] == target_year) &
            (df['Denial Date Month'] == target_month) &
            (df['Denial Date Day'] >= start_day) &
            (df['Denial Date Day'] <= end_day)
        ]
        
        # Group by classification for pie chart
        df_grouped = df.groupby("CLASSIFICATION", as_index=False).size().rename(columns={"size": "count"})
        
        # Prepare HTML tables per CLASSIFICATION (for popup) - include Category and Biller Role Type
        table_data = {}
        # Include these columns: Clinic, MRN, DOS, Payer, CPT, Reason, CATEGORY, Denial Date, User, ROLE_ID
        columns_to_include = ['Clinic', 'MRN', 'DOS', 'Payer', 'CPT', 'Reason', 'CATEGORY', 'Denial Date', 'User', 'ROLE_ID']
        # Ensure DOS and Denial Date are always in the list if they exist in df
        if 'DOS' in df.columns and 'DOS' not in columns_to_include:
            columns_to_include.append('DOS')
        if 'Denial Date' in df.columns and 'Denial Date' not in columns_to_include:
            columns_to_include.append('Denial Date')
        available_columns = [col for col in columns_to_include if col in df.columns]
        
        for cls in df["CLASSIFICATION"].unique():
            subset = df[df["CLASSIFICATION"] == cls][available_columns].copy()
            
            # Sort by Clinic name alphabetically
            subset = subset.sort_values(by="Clinic", ascending=True)
            
            # Create Biller Role Type column based on ROLE_ID
            def get_biller_role_type(role_id):
                if pd.isna(role_id):
                    return ''
                try:
                    role_id_int = int(role_id)
                    if role_id_int == 6:
                        return 'Biller'
                    elif role_id_int == 14:
                        return 'AR Biller'
                    else:
                        return ''
                except (ValueError, TypeError):
                    return ''
            
            # Always create Biller Role Type column (even if ROLE_ID is missing, it will be empty)
            if 'ROLE_ID' in subset.columns:
                subset['Biller Role Type'] = subset['ROLE_ID'].apply(get_biller_role_type)
            else:
                # If ROLE_ID column doesn't exist, create empty Biller Role Type column
                subset['Biller Role Type'] = ''
            
            # Rename CATEGORY to Category for display
            if 'CATEGORY' in subset.columns:
                subset.rename(columns={"CATEGORY": "Category"}, inplace=True)
            
            # Ensure all expected columns exist, even if empty
            for col in available_columns:
                if col not in subset.columns:
                    subset[col] = ''
            
            # Reorder to match expected column order (with Category and Biller Role Type)
            display_columns = ['Clinic', 'MRN', 'DOB', 'DOS', 'Payer', 'CPT', 'Reason', 'Category', 'Denial Date', 'User', 'Biller Role Type']
            display_columns = [col for col in display_columns if col in subset.columns]
            subset = subset[display_columns]
            
            # Format date columns to mm/dd/yyyy
            date_columns = ["DOB", "DOS", "Denial Date"]
            for col in date_columns:
                if col in subset.columns:
                    subset[col] = pd.to_datetime(subset[col], errors='coerce')
                    subset[col] = subset[col].dt.strftime('%m/%d/%Y').fillna('')
            
            table_data[cls] = subset.to_html(index=False, border=1)
        
        # Create labels with counts in brackets for legend
        labels_with_counts = [f"{cat} ({count})" for cat, count in zip(df_grouped["CLASSIFICATION"], df_grouped["count"])]
        
        # Format title with month and year
        target_date = pd.Timestamp(target_year, target_month, 1)
        month_name = target_date.strftime('%B')
        title = f"Denial Status for {category_range} {month_name} {target_year}"
        
        return {
            "categories": list(df_grouped["CLASSIFICATION"]),
            "counts": list(df_grouped["count"]),
            "labels_with_counts": labels_with_counts,
            "table_data": table_data,
            "title": title
        }

    # ============================
    # MONTHLY - Last month's data
    # ============================
    elif period == "monthly":
        # Get current date and calculate last month
        today = pd.Timestamp.now()
        # Get first day of last month
        if today.month == 1:
            last_month = 12
            last_month_year = today.year - 1
        else:
            last_month = today.month - 1
            last_month_year = today.year
        
        # Get first and last day of last month
        first_day_last_month = pd.Timestamp(last_month_year, last_month, 1).date()
        # Get last day of last month
        if last_month in [1, 3, 5, 7, 8, 10, 12]:  # 31-day months
            last_day_last_month = pd.Timestamp(last_month_year, last_month, 31).date()
        elif last_month in [4, 6, 9, 11]:  # 30-day months
            last_day_last_month = pd.Timestamp(last_month_year, last_month, 30).date()
        else:  # February
            # Check if leap year
            if (last_month_year % 4 == 0 and last_month_year % 100 != 0) or (last_month_year % 400 == 0):
                last_day_last_month = pd.Timestamp(last_month_year, last_month, 29).date()
            else:
                last_day_last_month = pd.Timestamp(last_month_year, last_month, 28).date()

        # Filter to last month's data
        df['Denial Date Date'] = df['Denial Date'].dt.date
        df = df[(df['Denial Date Date'] >= first_day_last_month) & (df['Denial Date Date'] <= last_day_last_month)]
        
        # Group by classification for pie chart
        df_grouped = df.groupby("CLASSIFICATION", as_index=False).size().rename(columns={"size": "count"})
        
        # Prepare HTML tables per CLASSIFICATION (for popup) - include Category and Biller Role Type
        table_data = {}
        # Include these columns: Clinic, MRN, DOS, Payer, CPT, Reason, CATEGORY, Denial Date, User, ROLE_ID
        columns_to_include = ['Clinic', 'MRN', 'DOS', 'Payer', 'CPT', 'Reason', 'CATEGORY', 'Denial Date', 'User', 'ROLE_ID']
        # Ensure DOS and Denial Date are always in the list if they exist in df
        if 'DOS' in df.columns and 'DOS' not in columns_to_include:
            columns_to_include.append('DOS')
        if 'Denial Date' in df.columns and 'Denial Date' not in columns_to_include:
            columns_to_include.append('Denial Date')
        available_columns = [col for col in columns_to_include if col in df.columns]
        
        for cls in df["CLASSIFICATION"].unique():
            subset = df[df["CLASSIFICATION"] == cls][available_columns].copy()
            
            # Sort by Clinic name alphabetically
            subset = subset.sort_values(by="Clinic", ascending=True)
            
            # Create Biller Role Type column based on ROLE_ID
            def get_biller_role_type(role_id):
                if pd.isna(role_id):
                    return ''
                try:
                    role_id_int = int(role_id)
                    if role_id_int == 6:
                        return 'Biller'
                    elif role_id_int == 14:
                        return 'AR Biller'
                    else:
                        return ''
                except (ValueError, TypeError):
                    return ''
            
            # Always create Biller Role Type column (even if ROLE_ID is missing, it will be empty)
            if 'ROLE_ID' in subset.columns:
                subset['Biller Role Type'] = subset['ROLE_ID'].apply(get_biller_role_type)
            else:
                # If ROLE_ID column doesn't exist, create empty Biller Role Type column
                subset['Biller Role Type'] = ''
            
            # Rename CATEGORY to Category for display
            if 'CATEGORY' in subset.columns:
                subset.rename(columns={"CATEGORY": "Category"}, inplace=True)
            
            # Ensure all expected columns exist, even if empty
            for col in available_columns:
                if col not in subset.columns:
                    subset[col] = ''
            
            # Reorder to match expected column order (with Category and Biller Role Type)
            display_columns = ['Clinic', 'MRN', 'DOB', 'DOS', 'Payer', 'CPT', 'Reason', 'Category', 'Denial Date', 'User', 'Biller Role Type']
            display_columns = [col for col in display_columns if col in subset.columns]
            subset = subset[display_columns]
            
            # Format date columns to mm/dd/yyyy
            date_columns = ["DOB", "DOS", "Denial Date"]
            for col in date_columns:
                if col in subset.columns:
                    subset[col] = pd.to_datetime(subset[col], errors='coerce')
                    subset[col] = subset[col].dt.strftime('%m/%d/%Y').fillna('')
            
            table_data[cls] = subset.to_html(index=False, border=1)
        
        # Create labels with counts in brackets for legend
        labels_with_counts = [f"{cat} ({count})" for cat, count in zip(df_grouped["CLASSIFICATION"], df_grouped["count"])]
        
        # Format title
        title = f"Denial Status on {pd.Timestamp(last_month_year, last_month, 1).strftime('%B %Y')}"

        return {
            "categories": list(df_grouped["CLASSIFICATION"]),
            "counts": list(df_grouped["count"]),
            "labels_with_counts": labels_with_counts,
            "table_data": table_data,
            "title": title
        }

    else:
        raise ValueError("Invalid period")

@app.get("/comparison-data")
def comparison_data(request: Request, period: str = "daily", date: str = None, week_end: str = None):
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    if period not in ["daily", "biweekly", "monthly"]:
        return JSONResponse(content={"error": "Invalid period."}, status_code=400)
    try:
        data = get_comparison_data_by_period(period, date=date, week_end=week_end)
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

# Clarification Grouping endpoint (using Denial Date)
def get_clarification_grouping_data():
    """Get clarification grouping data using Denial Date column (same as comparison button)"""
    df = get_denials_dataframe()
    # Trial date: 09/23/2025
    today = pd.Timestamp(2025, 9, 23)
    
    # Use Denial Date column instead of DATE
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    df["AGE_DAYS"] = (today - df["Denial Date"]).dt.days
    def categorize_age(age_days):
        if age_days < 18: return "<0.6months"
        if age_days < 365: return "0.6month-1yr"
        if age_days < 547: return "1-1.5yr"
        return ">1.5yr"
    df["TIME_RANGE"] = df["AGE_DAYS"].apply(categorize_age)
    time_ranges = ['<0.6months', '0.6month-1yr', '1-1.5yr', '>1.5yr']
    categories = sorted(df["CATEGORY"].unique())
    data = {"categories": categories}
    for rng in time_ranges:
        data[rng] = [0] * len(categories)
    grouped = df.groupby(["TIME_RANGE", "CATEGORY"]).size().reset_index(name="count")
    for _, row in grouped.iterrows():
        rng = row["TIME_RANGE"]; cat = row["CATEGORY"]; count = int(row["count"])
        if rng in data and cat in categories:
            data[rng][categories.index(cat)] = count
    return data

@app.get("/clarification-grouping-data")
def clarification_grouping_data(request: Request):
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_clarification_grouping_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

# Get all columns from WEEKLY_CLARIFICATION_DETAILS table
def get_weekly_clarification_columns():
    """Get all column names from WEEKLY_CLARIFICATION_DETAILS table"""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # Get database name from environment
        db_name = os.getenv("DB_DATABASE")
        query = """
            SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'WEEKLY_CLARIFICATION_DETAILS'
            ORDER BY ORDINAL_POSITION
        """
        cursor.execute(query, (db_name,))
        columns = []
        for row in cursor.fetchall():
            columns.append({
                "name": row[0].upper() if row[0] else "",
                "data_type": row[1].upper() if row[1] else "",
                "is_nullable": row[2].upper() if row[2] else "",
                "default": row[3].upper() if row[3] is not None and row[3] else ""
            })
        cursor.close()
        return {"columns": columns}
    except Exception as exc:
        raise Exception(f"Error fetching column information: {exc}")
    finally:
        conn.close()

@app.get("/get-weekly-clarification-columns")
def get_weekly_clarification_columns_endpoint(request: Request):
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_weekly_clarification_columns()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

# Clarification by Aging endpoint
# COMMENTED OUT FOR NOW
# All code below is commented out using if False block
if False:
    def get_clarification_by_aging_data():
        """Get clarification by aging data from Weekly_Clarification_Details table"""
        conn = get_connection()
        try:
            query = "SELECT CATEGORY as Category, Clari_Opened_Date FROM Weekly_Clarification_Details"
            df = pd.read_sql(query, conn)
        except Exception as exc:
            raise Exception(f"Error reading clarification data: {exc}")
        finally:
            conn.close()
        
        if df.empty:
            return {
                "categories": [],
                "series": {},
                "time_periods": ['0-6m', '6m-1y', '1-1.5y', '>1.5y']
            }
        
        # Convert date column
        df['Clari_Opened_Date'] = pd.to_datetime(df['Clari_Opened_Date'], errors='coerce')
        df = df.dropna(subset=['Clari_Opened_Date'])
        
        # Calculate age in days
        today = pd.Timestamp.now()
        df['AGE_DAYS'] = (today - df['Clari_Opened_Date']).dt.days
        
        # Categorize by age
        def categorize_age(age_days):
            if age_days < 180:  # 0-6 months (approximately 180 days)
                return '0-6m'
            elif age_days < 365:  # 6 months to 1 year
                return '6m-1y'
            elif age_days < 547:  # 1 to 1.5 years (approximately 547 days)
                return '1-1.5y'
            else:
                return '>1.5y'
        
        df['TIME_PERIOD'] = df['AGE_DAYS'].apply(categorize_age)
        
        # Get unique categories
        categories = sorted(df['Category'].unique())
        time_periods = ['0-6m', '6m-1y', '1-1.5y', '>1.5y']
        
        # Group by category and time period
        series_data = {}
        for cat in categories:
            series_data[cat] = []
            for period in time_periods:
                count = len(df[(df['Category'] == cat) & (df['TIME_PERIOD'] == period)])
                series_data[cat].append(count)
        
        return {
            "categories": categories,
            "series": series_data,
            "time_periods": time_periods
        }

    @app.get("/clarification-by-aging-data")
    def clarification_by_aging_data(request: Request):
        if not request.session.get("authenticated"):
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
        try:
            data = get_clarification_by_aging_data()
            return JSONResponse(content=data)
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

# Clarification Type endpoint (same logic as clarification grouping but without time grouping)
def get_clarification_type_data():
    """Get clarification type data using same logic as clarification grouping but without time ranges"""
    df = get_denials_dataframe()
    
    # Use Denial Date column (same as clarification grouping)
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    # Group by CATEGORY only (no time grouping)
    categories = sorted(df["CATEGORY"].unique())
    grouped = df.groupby("CATEGORY").size().reset_index(name="count")
    
    # Create counts list matching category order
    counts = []
    for cat in categories:
        cat_data = grouped[grouped["CATEGORY"] == cat]
        if not cat_data.empty:
            counts.append(int(cat_data.iloc[0]["count"]))
        else:
            counts.append(0)
    
    return {
        "categories": categories,
        "counts": counts
    }

@app.get("/clarification-type-data")
def clarification_type_data(request: Request):
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_clarification_type_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

# Legacy email/clarification endpoints (commented out).
if False:
    def get_email_comparison_data(type: str):
        entries_file = "entries.csv"
        completed_file = "files_completed.csv"
        # --- original CSV logic omitted for brevity ---
        return {}

    @app.get("/email-comparison-data")
    def email_comparison_data(request: Request, type: str):
        if not request.session.get("authenticated"):
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
        if type not in ["incoming", "completed", "pending"]:
            return JSONResponse(content={"error": "Invalid type."}, status_code=400)
        try:
            data = get_email_comparison_data(type)
            return JSONResponse(content=data)
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

    def get_clarification_data():
        df = get_denials_dataframe()
        today = pd.Timestamp.now()
        df["AGE_DAYS"] = (today - df["DATE"]).dt.days
        def categorize_age(age_days):
            if age_days < 18: return "<0.6months"
            if age_days < 365: return "0.6month-1yr"
            if age_days < 547: return "1-1.5yr"
            return ">1.5yr"
        df["TIME_RANGE"] = df["AGE_DAYS"].apply(categorize_age)
        time_ranges = ['<0.6months', '0.6month-1yr', '1-1.5yr', '>1.5yr']
        categories = sorted(df["CATEGORY"].unique())
        data = {"categories": categories}
        for rng in time_ranges:
            data[rng] = [0] * len(categories)
        grouped = df.groupby(["TIME_RANGE", "CATEGORY"]).size().reset_index(name="count")
        for _, row in grouped.iterrows():
            rng = row["TIME_RANGE"]; cat = row["CATEGORY"]; count = int(row["count"])
            if rng in data and cat in categories:
                data[rng][categories.index(cat)] = count
        return data

    @app.get("/clarification-data")
    def clarification_data(request: Request):
        if not request.session.get("authenticated"):
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
        try:
            data = get_clarification_data()
            return JSONResponse(content=data)
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_latest_denial_record():
    """Fetch the record with the latest denial date and return it as markdown formatted string"""
    df = get_denials_dataframe()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return "No denial records found."
    
    # Find the record with the latest denial date
    latest_idx = df['Denial Date'].idxmax()
    latest_record = df.loc[latest_idx]
    
    # Format as markdown
    md_output = "# Latest Denial Record\n\n"
    md_output += f"**Denial Date:** {latest_record['Denial Date'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(latest_record['Denial Date']) else 'N/A'}\n\n"
    md_output += f"**Clinic:** {latest_record.get('Clinic', 'N/A')}\n\n"
    md_output += f"**Patient Name:** {latest_record.get('Pt Name', 'N/A')}\n\n"
    md_output += f"**MRN:** {latest_record.get('MRN', 'N/A')}\n\n"
    md_output += f"**DOB:** {latest_record.get('DOB', 'N/A')}\n\n"
    md_output += f"**DOS:** {latest_record.get('DOS', 'N/A')}\n\n"
    md_output += f"**Payer:** {latest_record.get('Payer', 'N/A')}\n\n"
    md_output += f"**CPT:** {latest_record.get('CPT', 'N/A')}\n\n"
    md_output += f"**Reason:** {latest_record.get('Reason', 'N/A')}\n\n"
    md_output += f"**Category:** {latest_record.get('CATEGORY', 'N/A')}\n\n"
    md_output += f"**User:** {latest_record.get('User', 'N/A')}\n\n"
    md_output += f"**ROLE_ID:** {latest_record.get('ROLE_ID', 'N/A')}\n\n"
    
    return md_output

@app.get("/latest-denial")
def latest_denial(request: Request):
    """API endpoint to get the latest denial record as markdown"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        md_content = get_latest_denial_record()
        return HTMLResponse(content=f"<pre>{md_content}</pre>")
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_denials_comparison_data():
    """Get denial comparison data: current month vs previous month grouped by category"""
    df = get_denials_dataframe()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "current_month_counts": [],
            "previous_month_counts": [],
            "table_data": {}
        }
    
    # Get current date
    current_date = pd.Timestamp.now()
    current_year = current_date.year
    current_month = current_date.month
    
    # Calculate previous month
    if current_month == 1:
        previous_month = 12
        previous_year = current_year - 1
    else:
        previous_month = current_month - 1
        previous_year = current_year
    
    # Filter current month data
    df_current = df[
        (df['Denial Date'].dt.year == current_year) &
        (df['Denial Date'].dt.month == current_month)
    ]
    
    # Filter previous month data
    df_previous = df[
        (df['Denial Date'].dt.year == previous_year) &
        (df['Denial Date'].dt.month == previous_month)
    ]
    
    # Get all unique categories from both months
    all_categories = sorted(set(df['CATEGORY'].unique()))
    
    # Group by category for current month
    current_grouped = df_current.groupby('CATEGORY').size().reset_index(name='count')
    current_dict = dict(zip(current_grouped['CATEGORY'], current_grouped['count']))
    
    # Group by category for previous month
    previous_grouped = df_previous.groupby('CATEGORY').size().reset_index(name='count')
    previous_dict = dict(zip(previous_grouped['CATEGORY'], previous_grouped['count']))
    
    # Create counts arrays (in thousands) for all categories
    current_counts = [(current_dict.get(cat, 0) / 1000.0) for cat in all_categories]
    previous_counts = [(previous_dict.get(cat, 0) / 1000.0) for cat in all_categories]
    
    # Prepare table data for popups (full records for each category)
    table_data = {}
    for cat in all_categories:
        # Combine current and previous month data for this category
        cat_current = df_current[df_current['CATEGORY'] == cat]
        cat_previous = df_previous[df_previous['CATEGORY'] == cat]
        cat_all = pd.concat([cat_current, cat_previous], ignore_index=True)
        
        if not cat_all.empty:
            subset = cat_all[["Clinic", "Pt Name", "MRN", "DOB", "DOS", "Payer", "CPT", "Reason", "CATEGORY", "Denial Date", "User", "ROLE_ID"]].copy()
            subset = subset.sort_values(by="Clinic", ascending=True)
            table_data[cat] = subset.to_html(index=False, border=1)
        else:
            table_data[cat] = "<p>No data available for this category</p>"
    
    return {
        "categories": all_categories,
        "current_month_counts": current_counts,
        "previous_month_counts": previous_counts,
        "table_data": table_data,
        "current_month_label": f"{current_date.strftime('%B %Y')}",
        "previous_month_label": f"{pd.Timestamp(previous_year, previous_month, 1).strftime('%B %Y')}"
    }

@app.get("/denials-comparison-data")
def denials_comparison_data(request: Request):
    """API endpoint to get denial comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_denials_comparison_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_denials_biweekly_comparison_data():
    """Get biweekly denial comparison data for last 3 months, grouped by category"""
    df = get_denials_dataframe()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "periods": [],
            "data": {},
            "labels": []
        }
    
    # Get current date
    current_date = pd.Timestamp.now()
    
    # Get last 3 months
    periods = []
    labels = []
    for i in range(3):
        month_date = current_date - pd.DateOffset(months=i)
        year = month_date.year
        month = month_date.month
        
        # Get last day of month
        last_day = pd.Timestamp(year, month, 1) + pd.DateOffset(months=1) - pd.Timedelta(days=1)
        last_day_num = last_day.day
        
        # Create two biweekly periods
        periods.append({
            'year': year,
            'month': month,
            'start': 1,
            'end': 15,
            'label': f"{month_date.strftime('%b %Y')} (1-15)"
        })
        periods.append({
            'year': year,
            'month': month,
            'start': 16,
            'end': last_day_num,
            'label': f"{month_date.strftime('%b %Y')} (16-{last_day_num})"
        })
        labels.append(f"{month_date.strftime('%b %Y')} (1-15)")
        labels.append(f"{month_date.strftime('%b %Y')} (16-{last_day_num})")
    
    # Get all unique categories (using CATEGORY, not CLASSIFICATION)
    all_categories = sorted(set(df['CATEGORY'].unique()))
    
    # Prepare data for each period
    period_data = {}
    for period in periods:
        period_df = df[
            (df['Denial Date'].dt.year == period['year']) &
            (df['Denial Date'].dt.month == period['month']) &
            (df['Denial Date'].dt.day >= period['start']) &
            (df['Denial Date'].dt.day <= period['end'])
        ]
        
        # Group by category
        grouped = period_df.groupby('CATEGORY').size().reset_index(name='count')
        category_dict = dict(zip(grouped['CATEGORY'], grouped['count']))
        
        # Create counts array (in thousands) for all categories
        counts = [(category_dict.get(cat, 0) / 1000.0) for cat in all_categories]
        period_data[period['label']] = counts
    
    return {
        "categories": all_categories,
        "periods": labels,
        "data": period_data,
        "labels": labels
    }

@app.get("/denials-biweekly-comparison-data")
def denials_biweekly_comparison_data(request: Request):
    """API endpoint to get biweekly denial comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_denials_biweekly_comparison_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_denials_monthly_comparison_data():
    """Get monthly denial comparison data for last 6 months, grouped by category"""
    df = get_denials_dataframe()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "periods": [],
            "data": {},
            "labels": []
        }
    
    # Get current date
    current_date = pd.Timestamp.now()
    
    # Get last 6 months
    periods = []
    labels = []
    for i in range(6):
        month_date = current_date - pd.DateOffset(months=i)
        year = month_date.year
        month = month_date.month
        label = f"{month_date.strftime('%b %Y')}"
        
        periods.append({
            'year': year,
            'month': month,
            'label': label
        })
        labels.append(label)
    
    # Get all unique categories (using CATEGORY, not CLASSIFICATION)
    all_categories = sorted(set(df['CATEGORY'].unique()))
    
    # Prepare data for each period
    period_data = {}
    for period in periods:
        period_df = df[
            (df['Denial Date'].dt.year == period['year']) &
            (df['Denial Date'].dt.month == period['month'])
        ]
        
        # Group by category
        grouped = period_df.groupby('CATEGORY').size().reset_index(name='count')
        category_dict = dict(zip(grouped['CATEGORY'], grouped['count']))
        
        # Create counts array (in thousands) for all categories
        counts = [(category_dict.get(cat, 0) / 1000.0) for cat in all_categories]
        period_data[period['label']] = counts
    
    return {
        "categories": all_categories,
        "periods": labels,
        "data": period_data,
        "labels": labels
    }

@app.get("/denials-monthly-comparison-data")
def denials_monthly_comparison_data(request: Request):
    """API endpoint to get monthly denial comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_denials_monthly_comparison_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_users_by_role():
    """Get users grouped by role (Billing Team = ROLE_ID 6, A R Team = others)"""
    df = get_denials_dataframe()
    
    # Get unique users with their role IDs
    user_role_df = df[['User', 'ROLE_ID']].drop_duplicates()
    
    # Filter billing team (ROLE_ID == 6)
    billing_team = user_role_df[user_role_df['ROLE_ID'] == 6]['User'].dropna().unique().tolist()
    billing_team = [user for user in billing_team if user and str(user).strip()]  # Remove empty/None values
    billing_team.sort()
    
    # Filter A R Team (ROLE_ID != 6)
    ar_team = user_role_df[user_role_df['ROLE_ID'] != 6]['User'].dropna().unique().tolist()
    ar_team = [user for user in ar_team if user and str(user).strip()]  # Remove empty/None values
    ar_team.sort()
    
    return {
        "billing_team": billing_team,
        "ar_team": ar_team
    }

@app.get("/performance-users")
def performance_users(request: Request):
    """API endpoint to get users by role"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_users_by_role()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_user_denials_data(username):
    """Get denial data for a specific user, grouped by category"""
    df = get_denials_dataframe()
    
    # Filter by user
    df_user = df[df['User'] == username].copy()
    
    if df_user.empty:
        return {
            "categories": [],
            "counts": [],
            "labels_with_counts": [],
            "table_data": {}
        }
    
    # Use the same classification map as get_chart_data
    classification_map = {
        "Different insurance as primary": "Inactive or Wrong policy Information",
        "No active coverage": "Inactive or Wrong policy Information",
        "Wrong insurance": "Inactive or Wrong policy Information",
        "Wrong patient info": "Inactive or Wrong policy Information",
        "Wrong policy information": "Inactive or Wrong policy Information",
        "Prior to coverage": "Inactive or Wrong policy Information",
        "Missing/wrong Claim information": "Inactive or Wrong policy Information",
        "Covered under HMO Plan": "Inactive or Wrong policy Information",
        "Patient ineligible for this service": "Inactive or Wrong policy Information",
        "MCR paid more than MCD allowed amt": "Medicare paid more than Medicaid",
        "Medicare paid more than Medicaid": "Medicare paid more than Medicaid",
        "Primary paid more than sec allowed amount": "Medicare paid more than Medicaid",
        "Invalid DOS": "Incorrect/Invalid DOS",
        "Incorrect DOS": "Incorrect/Invalid DOS",
        "Timely filing limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal time limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal Not Allowed": "TFL/Appeal time limit expired or not allowed",
        "Appeal allowed": "TFL/Appeal time limit expired or not allowed",
        "Invalid CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing main CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong/Incorrect ICD Code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with DX.code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong POS": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Invalid number of units": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with provider speciality": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing Modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "EFT enrollment pending": "Provider enrollment issue",
        "Provider not eligible": "Provider enrollment issue",
        "Provider not enrolled": "Provider enrollment issue",
        "No Medicare credentialing": "Provider enrollment issue",
        "No Medicaid credentialing": "Provider enrollment issue",
        "Missing/invalid NPI of Billing provider in field 33a.": "Provider enrollment issue",
        "Missing/invalid NPI of Rendering Provider in field 24J.": "Provider enrollment issue",
        "Missing/invalid reffering Provider info": "Provider enrollment issue",
        "Out of Network": "Out of network",
        "Provider Out of Network": "Out of network",
        "no authorization": "Out of network",
        "Missing prior authorization": "Out of network",
        "Missing referral information": "Out of network",
        "Missing medical record": "Need additional information needed",
        "COB missing": "Need additional information needed",
        "Missing NDC code": "Need additional information needed",
        "Missing documentation": "Need additional information needed",
        "Missing EOB": "Need additional information needed",
        "Need Add-on-code": "Need additional information needed",
        "Need W9 form": "Need additional information needed",
        "Accident Info required": "Need additional information needed",
        "Missing illness information": "Need additional information needed",
        "No Medical Necessity": "Need additional information needed",
        "Pre-existing condition": "Need additional information needed",
        "Itemized bill needed": "Need additional information needed",
        "Clinical Review Determination": "Need additional information needed",
        "Non covered service": "Non covered service",
        "non covered submitted via paper": "Non covered service",
        "Charges too high": "Other",
        "Claim previously paid": "Other",
        "Contractual obligation": "Other",
        "Date of death precedes DOS": "Other",
        "Duplicate claim": "Other",
        "Exceeds clinical guidelines": "Other",
        "Invalid redetermination": "Other",
        "Managed care withholding": "Other",
        "Not met residency requirement": "Other",
        "Other": "Other",
        "Participating Provider Discount": "Other",
        "Patient in Hospice": "Other",
        "Patient incarcerated": "Other",
        "Payment made to another provider": "Other",
        "The qualifying service has not been received": "Other",
        "Claim Adjustment Due to Resubmission": "Incorrect Billing",
        "Incorrect Patient Billing": "Incorrect Billing",
        "Corrected Claim": "Incorrect Billing",
        "Resubmit the claim": "Incorrect Billing",
        "Invalid Taxpayer ID": "Incorrect Billing",
        "Revised claim with new claim number": "Incorrect Billing",
        "Invalid discharge date": "Incorrect Billing",
        "Charges exceeded, maximum allowed": "Incorrect Billing",
        "Negotiated discount": "Bundled service",
        "Benefit limited": "Bundled service",
        "Incidental Service": "Bundled service",
        "Max benefit exceeded": "Bundled service"
    }
    
    # Map CATEGORY to classification
    df_user['CLASSIFICATION'] = df_user['CATEGORY'].map(classification_map).fillna('Other')
    
    # Group by classification for pie chart
    df_grouped = df_user.groupby("CLASSIFICATION", as_index=False).size().rename(columns={"size": "count"})
    
    # Prepare HTML tables per CLASSIFICATION (for popup)
    table_data = {}
    for cls in df_user["CLASSIFICATION"].unique():
        subset = df_user[df_user["CLASSIFICATION"] == cls][["Clinic", "Pt Name", "MRN", "DOB", "DOS", "Payer", "CPT", "Reason", "CATEGORY", "Denial Date", "User", "ROLE_ID"]].copy()
        subset = subset.sort_values(by="Clinic", ascending=True)
        
        # Create Biller Role Type column based on ROLE_ID
        def get_biller_role_type(role_id):
            if pd.isna(role_id):
                return ''
            try:
                role_id_int = int(role_id)
                if role_id_int == 6:
                    return 'Biller'
                else:
                    return 'A R Biller'
            except (ValueError, TypeError):
                return ''
        
        subset['Biller Role Type'] = subset['ROLE_ID'].apply(get_biller_role_type)
        
        # Drop ROLE_ID and rename columns for display
        subset = subset.drop(columns=['ROLE_ID'])
        # Reorder columns to put Biller Role Type at the end
        cols = ["Clinic", "Pt Name", "MRN", "DOB", "DOS", "Payer", "CPT", "Reason", "CATEGORY", "Denial Date", "User", "Biller Role Type"]
        subset = subset[[col for col in cols if col in subset.columns]]
        
        # Format date columns to mm/dd/yyyy
        date_columns = ["DOB", "DOS", "Denial Date"]
        for col in date_columns:
            if col in subset.columns:
                # Convert to datetime if not already, handling errors
                subset[col] = pd.to_datetime(subset[col], errors='coerce')
                # Format to mm/dd/yyyy, replacing NaT with empty string
                subset[col] = subset[col].dt.strftime('%m/%d/%Y').fillna('')
        
        table_data[cls] = subset.to_html(index=False, border=1)
    
    # Create labels with counts in brackets for legend
    labels_with_counts = [f"{cat} ({count})" for cat, count in zip(df_grouped["CLASSIFICATION"], df_grouped["count"])]
    
    # Serialize data safely for embedding into JS
    js_categories = list(df_grouped["CLASSIFICATION"])
    js_counts = list(df_grouped["count"])
    js_labels_with_counts = labels_with_counts
    js_table_data = table_data
    
    return {
        "categories": js_categories,
        "counts": js_counts,
        "labels_with_counts": js_labels_with_counts,
        "table_data": js_table_data
    }

@app.get("/user-denials-data")
def user_denials_data(request: Request, username: str):
    """API endpoint to get denial data for a specific user"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_user_denials_data(username)
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_biweekly_comparison_data():
    """Get biweekly comparison data for last 3 months"""
    df = get_denials_dataframe()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "periods": [],
            "data": {},
            "labels": []
        }
    
    # Get current date
    current_date = pd.Timestamp.now()
    
    # Get last 3 months
    periods = []
    labels = []
    for i in range(3):
        month_date = current_date - pd.DateOffset(months=i)
        year = month_date.year
        month = month_date.month
        
        # Get last day of month
        last_day = pd.Timestamp(year, month, 1) + pd.DateOffset(months=1) - pd.Timedelta(days=1)
        last_day_num = last_day.day
        
        # Create two biweekly periods
        periods.append({
            'year': year,
            'month': month,
            'start': 1,
            'end': 15,
            'label': f"{month_date.strftime('%b %Y')} (1-15)"
        })
        periods.append({
            'year': year,
            'month': month,
            'start': 16,
            'end': last_day_num,
            'label': f"{month_date.strftime('%b %Y')} (16-{last_day_num})"
        })
        labels.append(f"{month_date.strftime('%b %Y')} (1-15)")
        labels.append(f"{month_date.strftime('%b %Y')} (16-{last_day_num})")
    
    # Get all unique classifications
    all_categories = sorted(set(df['CLASSIFICATION'].unique()))
    
    # Prepare data for each period
    period_data = {}
    for period in periods:
        period_df = df[
            (df['Denial Date'].dt.year == period['year']) &
            (df['Denial Date'].dt.month == period['month']) &
            (df['Denial Date'].dt.day >= period['start']) &
            (df['Denial Date'].dt.day <= period['end'])
        ]
        
        # Group by classification
        grouped = period_df.groupby('CLASSIFICATION').size().reset_index(name='count')
        category_dict = dict(zip(grouped['CLASSIFICATION'], grouped['count']))
        
        # Create counts array (in thousands) for all categories
        counts = [(category_dict.get(cat, 0) / 1000.0) for cat in all_categories]
        period_data[period['label']] = counts
    
    return {
        "categories": all_categories,
        "periods": labels,
        "data": period_data,
        "labels": labels
    }

@app.get("/biweekly-comparison-data")
def biweekly_comparison_data(request: Request):
    """API endpoint to get biweekly comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_biweekly_comparison_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_monthly_comparison_data():
    """Get monthly comparison data for last 6 months"""
    df = get_denials_dataframe()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "periods": [],
            "data": {},
            "labels": []
        }
    
    # Use the same classification map as get_chart_data
    classification_map = {
        "Different insurance as primary": "Inactive or Wrong policy Information",
        "No active coverage": "Inactive or Wrong policy Information",
        "Wrong insurance": "Inactive or Wrong policy Information",
        "Wrong patient info": "Inactive or Wrong policy Information",
        "Wrong policy information": "Inactive or Wrong policy Information",
        "Prior to coverage": "Inactive or Wrong policy Information",
        "Missing/wrong Claim information": "Inactive or Wrong policy Information",
        "Covered under HMO Plan": "Inactive or Wrong policy Information",
        "Patient ineligible for this service": "Inactive or Wrong policy Information",
        "MCR paid more than MCD allowed amt": "Medicare paid more than Medicaid",
        "Medicare paid more than Medicaid": "Medicare paid more than Medicaid",
        "Primary paid more than sec allowed amount": "Medicare paid more than Medicaid",
        "Invalid DOS": "Incorrect/Invalid DOS",
        "Incorrect DOS": "Incorrect/Invalid DOS",
        "Timely filing limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal time limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal Not Allowed": "TFL/Appeal time limit expired or not allowed",
        "Appeal allowed": "TFL/Appeal time limit expired or not allowed",
        "Invalid CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing main CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong/Incorrect ICD Code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with DX.code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong POS": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Invalid number of units": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with provider speciality": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing Modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "EFT enrollment pending": "Provider enrollment issue",
        "Provider not eligible": "Provider enrollment issue",
        "Provider not enrolled": "Provider enrollment issue",
        "No Medicare credentialing": "Provider enrollment issue",
        "No Medicaid credentialing": "Provider enrollment issue",
        "Missing/invalid NPI of Billing provider in field 33a.": "Provider enrollment issue",
        "Missing/invalid NPI of Rendering Provider in field 24J.": "Provider enrollment issue",
        "Missing/invalid reffering Provider info": "Provider enrollment issue",
        "Out of Network": "Out of network",
        "Provider Out of Network": "Out of network",
        "no authorization": "Out of network",
        "Missing prior authorization": "Out of network",
        "Missing referral information": "Out of network",
        "Missing medical record": "Need additional information needed",
        "COB missing": "Need additional information needed",
        "Missing NDC code": "Need additional information needed",
        "Missing documentation": "Need additional information needed",
        "Missing EOB": "Need additional information needed",
        "Need Add-on-code": "Need additional information needed",
        "Need W9 form": "Need additional information needed",
        "Accident Info required": "Need additional information needed",
        "Missing illness information": "Need additional information needed",
        "No Medical Necessity": "Need additional information needed",
        "Pre-existing condition": "Need additional information needed",
        "Itemized bill needed": "Need additional information needed",
        "Clinical Review Determination": "Need additional information needed",
        "Non covered service": "Non covered service",
        "non covered submitted via paper": "Non covered service",
        "Charges too high": "Other",
        "Claim previously paid": "Other",
        "Contractual obligation": "Other",
        "Date of death precedes DOS": "Other",
        "Duplicate claim": "Other",
        "Exceeds clinical guidelines": "Other",
        "Invalid redetermination": "Other",
        "Managed care withholding": "Other",
        "Not met residency requirement": "Other",
        "Other": "Other",
        "Participating Provider Discount": "Other",
        "Patient in Hospice": "Other",
        "Patient incarcerated": "Other",
        "Payment made to another provider": "Other",
        "The qualifying service has not been received": "Other",
        "Claim Adjustment Due to Resubmission": "Incorrect Billing",
        "Incorrect Patient Billing": "Incorrect Billing",
        "Corrected Claim": "Incorrect Billing",
        "Resubmit the claim": "Incorrect Billing",
        "Invalid Taxpayer ID": "Incorrect Billing",
        "Revised claim with new claim number": "Incorrect Billing",
        "Invalid discharge date": "Incorrect Billing",
        "Charges exceeded, maximum allowed": "Incorrect Billing",
        "Negotiated discount": "Bundled service",
        "Benefit limited": "Bundled service",
        "Incidental Service": "Bundled service",
        "Max benefit exceeded": "Bundled service"
    }
    
    # Map CATEGORY to classification
    df['CLASSIFICATION'] = df['CATEGORY'].map(classification_map).fillna('Other')
    
    # Get current date
    current_date = pd.Timestamp.now()
    
    # Get last 6 months
    periods = []
    labels = []
    for i in range(6):
        month_date = current_date - pd.DateOffset(months=i)
        year = month_date.year
        month = month_date.month
        
        periods.append({
            'year': year,
            'month': month,
            'label': month_date.strftime('%b %Y')
        })
        labels.append(month_date.strftime('%b %Y'))
    
    # Get all unique classifications
    all_categories = sorted(set(df['CLASSIFICATION'].unique()))
    
    # Prepare data for each period
    period_data = {}
    for period in periods:
        period_df = df[
            (df['Denial Date'].dt.year == period['year']) &
            (df['Denial Date'].dt.month == period['month'])
        ]
        
        # Group by classification
        grouped = period_df.groupby('CLASSIFICATION').size().reset_index(name='count')
        category_dict = dict(zip(grouped['CLASSIFICATION'], grouped['count']))
        
        # Create counts array (in thousands) for all categories
        counts = [(category_dict.get(cat, 0) / 1000.0) for cat in all_categories]
        period_data[period['label']] = counts
    
    return {
        "categories": all_categories,
        "periods": labels,
        "data": period_data,
        "labels": labels
    }

@app.get("/monthly-comparison-data")
def monthly_comparison_data(request: Request):
    """API endpoint to get monthly comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        data = get_monthly_comparison_data()
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_biweekly_user_comparison_data(username):
    """Get biweekly comparison data for selected user for last 3 months, grouped by category"""
    df = get_denials_dataframe()
    
    # Filter by selected user
    df = df[df['User'] == username].copy()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "periods": [],
            "data": {},
            "labels": []
        }
    
    # Use the same classification map as get_chart_data
    classification_map = {
        "Different insurance as primary": "Inactive or Wrong policy Information",
        "No active coverage": "Inactive or Wrong policy Information",
        "Wrong insurance": "Inactive or Wrong policy Information",
        "Wrong patient info": "Inactive or Wrong policy Information",
        "Wrong policy information": "Inactive or Wrong policy Information",
        "Prior to coverage": "Inactive or Wrong policy Information",
        "Missing/wrong Claim information": "Inactive or Wrong policy Information",
        "Covered under HMO Plan": "Inactive or Wrong policy Information",
        "Patient ineligible for this service": "Inactive or Wrong policy Information",
        "MCR paid more than MCD allowed amt": "Medicare paid more than Medicaid",
        "Medicare paid more than Medicaid": "Medicare paid more than Medicaid",
        "Primary paid more than sec allowed amount": "Medicare paid more than Medicaid",
        "Invalid DOS": "Incorrect/Invalid DOS",
        "Incorrect DOS": "Incorrect/Invalid DOS",
        "Timely filing limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal time limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal Not Allowed": "TFL/Appeal time limit expired or not allowed",
        "Appeal allowed": "TFL/Appeal time limit expired or not allowed",
        "Invalid CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing main CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong/Incorrect ICD Code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with DX.code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong POS": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Invalid number of units": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with provider speciality": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing Modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "EFT enrollment pending": "Provider enrollment issue",
        "Provider not eligible": "Provider enrollment issue",
        "Provider not enrolled": "Provider enrollment issue",
        "No Medicare credentialing": "Provider enrollment issue",
        "No Medicaid credentialing": "Provider enrollment issue",
        "Missing/invalid NPI of Billing provider in field 33a.": "Provider enrollment issue",
        "Missing/invalid NPI of Rendering Provider in field 24J.": "Provider enrollment issue",
        "Missing/invalid reffering Provider info": "Provider enrollment issue",
        "Out of Network": "Out of network",
        "Provider Out of Network": "Out of network",
        "no authorization": "Out of network",
        "Missing prior authorization": "Out of network",
        "Missing referral information": "Out of network",
        "Missing medical record": "Need additional information needed",
        "COB missing": "Need additional information needed",
        "Missing NDC code": "Need additional information needed",
        "Missing documentation": "Need additional information needed",
        "Missing EOB": "Need additional information needed",
        "Need Add-on-code": "Need additional information needed",
        "Need W9 form": "Need additional information needed",
        "Accident Info required": "Need additional information needed",
        "Missing illness information": "Need additional information needed",
        "No Medical Necessity": "Need additional information needed",
        "Pre-existing condition": "Need additional information needed",
        "Itemized bill needed": "Need additional information needed",
        "Clinical Review Determination": "Need additional information needed",
        "Non covered service": "Non covered service",
        "non covered submitted via paper": "Non covered service",
        "Charges too high": "Other",
        "Claim previously paid": "Other",
        "Contractual obligation": "Other",
        "Date of death precedes DOS": "Other",
        "Duplicate claim": "Other",
        "Exceeds clinical guidelines": "Other",
        "Invalid redetermination": "Other",
        "Managed care withholding": "Other",
        "Not met residency requirement": "Other",
        "Other": "Other",
        "Participating Provider Discount": "Other",
        "Patient in Hospice": "Other",
        "Patient incarcerated": "Other",
        "Payment made to another provider": "Other",
        "The qualifying service has not been received": "Other",
        "Claim Adjustment Due to Resubmission": "Incorrect Billing",
        "Incorrect Patient Billing": "Incorrect Billing",
        "Corrected Claim": "Incorrect Billing",
        "Resubmit the claim": "Incorrect Billing",
        "Invalid Taxpayer ID": "Incorrect Billing",
        "Revised claim with new claim number": "Incorrect Billing",
        "Invalid discharge date": "Incorrect Billing",
        "Charges exceeded, maximum allowed": "Incorrect Billing",
        "Negotiated discount": "Bundled service",
        "Benefit limited": "Bundled service",
        "Incidental Service": "Bundled service",
        "Max benefit exceeded": "Bundled service"
    }
    
    # Map CATEGORY to classification
    df['CLASSIFICATION'] = df['CATEGORY'].map(classification_map).fillna('Other')
    
    # Get current date
    current_date = pd.Timestamp.now()
    
    # Get last 3 months
    periods = []
    labels = []
    for i in range(3):
        month_date = current_date - pd.DateOffset(months=i)
        year = month_date.year
        month = month_date.month
        
        # Get last day of month
        last_day = pd.Timestamp(year, month, 1) + pd.DateOffset(months=1) - pd.Timedelta(days=1)
        last_day_num = last_day.day
        
        # Create two biweekly periods
        periods.append({
            'year': year,
            'month': month,
            'start': 1,
            'end': 15,
            'label': f"{month_date.strftime('%b %Y')} (1-15)"
        })
        periods.append({
            'year': year,
            'month': month,
            'start': 16,
            'end': last_day_num,
            'label': f"{month_date.strftime('%b %Y')} (16-{last_day_num})"
        })
        labels.append(f"{month_date.strftime('%b %Y')} (1-15)")
        labels.append(f"{month_date.strftime('%b %Y')} (16-{last_day_num})")
    
    # Get all unique classifications
    all_categories = sorted(set(df['CLASSIFICATION'].unique()))
    
    # Prepare data for each period
    period_data = {}
    for period in periods:
        period_df = df[
            (df['Denial Date'].dt.year == period['year']) &
            (df['Denial Date'].dt.month == period['month']) &
            (df['Denial Date'].dt.day >= period['start']) &
            (df['Denial Date'].dt.day <= period['end'])
        ]
        
        # Group by classification
        grouped = period_df.groupby('CLASSIFICATION').size().reset_index(name='count')
        category_dict = dict(zip(grouped['CLASSIFICATION'], grouped['count']))
        
        # Create counts array (in thousands) for all categories
        counts = [(category_dict.get(cat, 0) / 1000.0) for cat in all_categories]
        period_data[period['label']] = counts
    
    return {
        "categories": all_categories,
        "periods": labels,
        "data": period_data,
        "labels": labels
    }

@app.get("/biweekly-user-comparison-data")
def biweekly_user_comparison_data(request: Request):
    """API endpoint to get biweekly user comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        username = request.query_params.get('username')
        if not username:
            return JSONResponse(content={"error": "No user selected"}, status_code=400)
        data = get_biweekly_user_comparison_data(username)
        return JSONResponse(content=data)
    except Exception as e:
        import traceback
        return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

def get_monthly_user_comparison_data(username):
    """Get monthly comparison data for selected user for last 6 months, grouped by category"""
    df = get_denials_dataframe()
    
    # Filter by selected user
    df = df[df['User'] == username].copy()
    
    # Convert Denial Date to datetime
    df['Denial Date'] = pd.to_datetime(df['Denial Date'], errors='coerce')
    df = df.dropna(subset=['Denial Date'])
    
    if df.empty:
        return {
            "categories": [],
            "periods": [],
            "data": {},
            "labels": []
        }
    
    # Use the same classification map as get_chart_data
    classification_map = {
        "Different insurance as primary": "Inactive or Wrong policy Information",
        "No active coverage": "Inactive or Wrong policy Information",
        "Wrong insurance": "Inactive or Wrong policy Information",
        "Wrong patient info": "Inactive or Wrong policy Information",
        "Wrong policy information": "Inactive or Wrong policy Information",
        "Prior to coverage": "Inactive or Wrong policy Information",
        "Missing/wrong Claim information": "Inactive or Wrong policy Information",
        "Covered under HMO Plan": "Inactive or Wrong policy Information",
        "Patient ineligible for this service": "Inactive or Wrong policy Information",
        "MCR paid more than MCD allowed amt": "Medicare paid more than Medicaid",
        "Medicare paid more than Medicaid": "Medicare paid more than Medicaid",
        "Primary paid more than sec allowed amount": "Medicare paid more than Medicaid",
        "Invalid DOS": "Incorrect/Invalid DOS",
        "Incorrect DOS": "Incorrect/Invalid DOS",
        "Timely filing limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal time limit exceeded": "TFL/Appeal time limit expired or not allowed",
        "Appeal Not Allowed": "TFL/Appeal time limit expired or not allowed",
        "Appeal allowed": "TFL/Appeal time limit expired or not allowed",
        "Invalid CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing main CPT code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong/Incorrect ICD Code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with DX.code": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Wrong POS": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Invalid number of units": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "CPT inconsistent with provider speciality": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "Missing Modifier": "Missing or Invalid ICD/CPT code/Modifier/POS",
        "EFT enrollment pending": "Provider enrollment issue",
        "Provider not eligible": "Provider enrollment issue",
        "Provider not enrolled": "Provider enrollment issue",
        "No Medicare credentialing": "Provider enrollment issue",
        "No Medicaid credentialing": "Provider enrollment issue",
        "Missing/invalid NPI of Billing provider in field 33a.": "Provider enrollment issue",
        "Missing/invalid NPI of Rendering Provider in field 24J.": "Provider enrollment issue",
        "Missing/invalid reffering Provider info": "Provider enrollment issue",
        "Out of Network": "Out of network",
        "Provider Out of Network": "Out of network",
        "no authorization": "Out of network",
        "Missing prior authorization": "Out of network",
        "Missing referral information": "Out of network",
        "Missing medical record": "Need additional information needed",
        "COB missing": "Need additional information needed",
        "Missing NDC code": "Need additional information needed",
        "Missing documentation": "Need additional information needed",
        "Missing EOB": "Need additional information needed",
        "Need Add-on-code": "Need additional information needed",
        "Need W9 form": "Need additional information needed",
        "Accident Info required": "Need additional information needed",
        "Missing illness information": "Need additional information needed",
        "No Medical Necessity": "Need additional information needed",
        "Pre-existing condition": "Need additional information needed",
        "Itemized bill needed": "Need additional information needed",
        "Clinical Review Determination": "Need additional information needed",
        "Non covered service": "Non covered service",
        "non covered submitted via paper": "Non covered service",
        "Charges too high": "Other",
        "Claim previously paid": "Other",
        "Contractual obligation": "Other",
        "Date of death precedes DOS": "Other",
        "Duplicate claim": "Other",
        "Exceeds clinical guidelines": "Other",
        "Invalid redetermination": "Other",
        "Managed care withholding": "Other",
        "Not met residency requirement": "Other",
        "Other": "Other",
        "Participating Provider Discount": "Other",
        "Patient in Hospice": "Other",
        "Patient incarcerated": "Other",
        "Payment made to another provider": "Other",
        "The qualifying service has not been received": "Other",
        "Claim Adjustment Due to Resubmission": "Incorrect Billing",
        "Incorrect Patient Billing": "Incorrect Billing",
        "Corrected Claim": "Incorrect Billing",
        "Resubmit the claim": "Incorrect Billing",
        "Invalid Taxpayer ID": "Incorrect Billing",
        "Revised claim with new claim number": "Incorrect Billing",
        "Invalid discharge date": "Incorrect Billing",
        "Charges exceeded, maximum allowed": "Incorrect Billing",
        "Negotiated discount": "Bundled service",
        "Benefit limited": "Bundled service",
        "Incidental Service": "Bundled service",
        "Max benefit exceeded": "Bundled service"
    }
    
    # Map CATEGORY to classification
    df['CLASSIFICATION'] = df['CATEGORY'].map(classification_map).fillna('Other')
    
    # Get current date
    current_date = pd.Timestamp.now()
    
    # Get last 6 months
    periods = []
    labels = []
    for i in range(6):
        month_date = current_date - pd.DateOffset(months=i)
        year = month_date.year
        month = month_date.month
        
        periods.append({
            'year': year,
            'month': month,
            'label': month_date.strftime('%b %Y')
        })
        labels.append(month_date.strftime('%b %Y'))
    
    # Get all unique classifications
    all_categories = sorted(set(df['CLASSIFICATION'].unique()))
    
    # Prepare data for each period
    period_data = {}
    for period in periods:
        period_df = df[
            (df['Denial Date'].dt.year == period['year']) &
            (df['Denial Date'].dt.month == period['month'])
        ]
        
        # Group by classification
        grouped = period_df.groupby('CLASSIFICATION').size().reset_index(name='count')
        category_dict = dict(zip(grouped['CLASSIFICATION'], grouped['count']))
        
        # Create counts array (in thousands) for all categories
        counts = [(category_dict.get(cat, 0) / 1000.0) for cat in all_categories]
        period_data[period['label']] = counts
    
    return {
        "categories": all_categories,
        "periods": labels,
        "data": period_data,
        "labels": labels
    }

@app.get("/monthly-user-comparison-data")
def monthly_user_comparison_data(request: Request):
    """API endpoint to get monthly user comparison data"""
    if not request.session.get("authenticated"):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    try:
        username = request.query_params.get('username')
        if not username:
            return JSONResponse(content={"error": "No user selected"}, status_code=400)
        data = get_monthly_user_comparison_data(username)
        return JSONResponse(content=data)
    except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

