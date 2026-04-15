"""
Authentication Module for Insider Threat Detection Dashboard

Provides login, session management, and user authentication.
"""

import streamlit as st
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.alert_database import (
    verify_user, create_session, validate_session,
    change_password, init_database, log_audit
)
import hashlib

def check_auth():
    """Check if user is authenticated."""
    # Initialize database if not exists
    init_database()

    # Check if already logged in
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if 'session_id' not in st.session_state:
        st.session_state['session_id'] = None

    # Validate existing session
    if st.session_state['logged_in'] and st.session_state['session_id']:
        if not validate_session(st.session_state['session_id']):
            st.session_state['logged_in'] = False
            st.session_state['session_id'] = None
            return False
        return True

    return False

def login_page():
    """Render the login page with stunning visuals."""
    st.set_page_config(
        page_title="Insider Threat Detection - Login",
        page_icon="🔒",
        layout="centered"
    )

    # Custom CSS for stunning visual effects
    st.markdown("""
    <style>
    /* Main container styling */
    .stApp {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        min-height: 100vh;
    }

    /* Login box styling */
    .login-container {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        padding: 40px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        max-width: 450px;
        margin: 50px auto;
    }

    /* Title styling */
    .login-title {
        text-align: center;
        color: #e94560;
        font-size: 2.5em;
        font-weight: bold;
        margin-bottom: 10px;
        text-shadow: 0 0 20px rgba(233, 69, 96, 0.5);
    }

    .login-subtitle {
        text-align: center;
        color: #a0a0a0;
        font-size: 1.1em;
        margin-bottom: 30px;
    }

    /* Input field styling */
    .stTextInput > div > div > input {
        background: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
        color: white;
        border-radius: 10px;
        padding: 12px 20px;
    }

    .stTextInput > div > div > input:focus {
        border-color: #e94560;
        box-shadow: 0 0 15px rgba(233, 69, 96, 0.3);
    }

    .stTextInput label {
        color: #ffffff;
        font-weight: 500;
    }

    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #e94560 0%, #c73e54 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 15px 30px;
        font-size: 1.1em;
        font-weight: bold;
        width: 100%;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(233, 69, 96, 0.4);
    }

    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(233, 69, 96, 0.6);
    }

    /* Error message styling */
    .stAlert > div {
        background: rgba(233, 69, 96, 0.2);
        border: 1px solid #e94560;
        color: #ff6b6b;
        border-radius: 10px;
    }

    /* Success message styling */
    .success-alert > div {
        background: rgba(46, 204, 113, 0.2);
        border: 1px solid #2ecc71;
        color: #2ecc71;
        border-radius: 10px;
    }

    /* Network animation background */
    .network-bg {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: -1;
        background: radial-gradient(ellipse at center, #1b2735 0%, #090a0f 100%);
    }

    .network-node {
        position: absolute;
        background: rgba(233, 69, 96, 0.6);
        border-radius: 50%;
        animation: pulse 3s infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 0.3; transform: scale(1); }
        50% { opacity: 0.8; transform: scale(1.2); }
    }

    /* Divider */
    .divider {
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        margin: 20px 0;
    }

    /* Footer */
    .login-footer {
        text-align: center;
        color: #666;
        font-size: 0.9em;
        margin-top: 30px;
    }

    /* Hide default Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

    # Animated background effect (simplified)
    st.markdown('<div class="network-bg"></div>', unsafe_allow_html=True)

    # Main login container
    st.markdown("""
    <div class="login-container">
        <div class="login-title">🔒 Insider Threat Detection</div>
        <div class="login-subtitle">Security Operations Center</div>
    </div>
    """, unsafe_allow_html=True)

    # Login form
    with st.form(key='login_form', clear_on_submit=False):
        st.markdown("### Sign In")

        username = st.text_input(
            "Username",
            placeholder="Enter your username",
            key='username_input'
        )

        password = st.text_input(
            "Password",
            type="password",
            placeholder="Enter your password",
            key='password_input'
        )

        login_button = st.form_submit_button("🔐 Login", use_container_width=True)

        if login_button:
            if username and password:
                if verify_user(username, password):
                    st.session_state['logged_in'] = True
                    st.session_state['session_id'] = create_session(username)
                    st.session_state['username'] = username
                    log_audit(username, 'login_successful')
                    st.success("Login successful! Redirecting...")
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
                    log_audit(username, 'login_failed', details={'reason': 'invalid_credentials'})
            else:
                st.error("Please enter both username and password")

    # Footer
    st.markdown("""
    <div class="login-footer">
        <p>Authorized Personnel Only | All activities are monitored</p>
        <p>© 2024 Insider Threat Detection System</p>
    </div>
    """, unsafe_allow_html=True)

def logout():
    """Log out the current user."""
    if st.session_state.get('username'):
        log_audit(st.session_state['username'], 'logout')
    st.session_state['logged_in'] = False
    st.session_state['session_id'] = None
    st.session_state['username'] = None
    st.rerun()

def show_user_menu():
    """Show user menu in sidebar with logout and password change options."""
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"👤 **Logged in as:** `{st.session_state.get('username', 'Unknown')}`")

    # User menu in sidebar
    menu = st.sidebar.selectbox(
        "Account",
        ["View Profile", "Change Password", "Logout"],
        key='user_menu_select'
    )

    if menu == "Logout":
        logout()
    elif menu == "Change Password":
        show_change_password_form()
    elif menu == "View Profile":
        st.sidebar.info(f"""
        **Username:** {st.session_state.get('username', 'Unknown')}
        **Role:** Analyst
        **Status:** Active
        """)

def show_change_password_form():
    """Show change password form."""
    st.sidebar.markdown("### Change Password")

    with st.sidebar.form(key='change_password_form'):
        old_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")

        if st.form_submit_button("Change Password"):
            if not old_password or not new_password or not confirm_password:
                st.error("All fields are required")
            elif new_password != confirm_password:
                st.error("New passwords do not match")
            elif len(new_password) < 4:
                st.error("Password must be at least 4 characters")
            else:
                if change_password(st.session_state.get('username'), old_password, new_password):
                    st.success("Password changed successfully!")
                    st.rerun()
                else:
                    st.error("Current password is incorrect")
