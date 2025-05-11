import streamlit as st
import json
import os
import base64
import hashlib
import uuid
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

DATA_FILE = 'data_store.json'
LOCKOUT_DURATION = timedelta(minutes=5)
PBKDF2_ITERATIONS = 100_000

# --- Helper Functions ---

def load_data():
    if not os.path.exists(DATA_FILE):
        return {'users': {}}
    with open(DATA_FILE, 'r') as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)


def pbkdf2_hash(passkey: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, PBKDF2_ITERATIONS)


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_fernet_key(passkey: str, salt: bytes) -> bytes:
    # Derive 32-byte key and urlsafe base64 encode
    key = pbkdf2_hash(passkey, salt)
    return base64.urlsafe_b64encode(key)


# --- Initialization ---
if 'data' not in st.session_state:
    st.session_state.data = load_data()

# Authentication state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.attempts = 0

# --- Pages ---

def signup():
    st.header("🔐 Sign Up")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    confirm = st.text_input("Confirm Passkey", type="password")
    if st.button("Create Account"):
        if not username or not passkey:
            st.error("Fill all fields.")
            return
        if passkey != confirm:
            st.error("Passkeys do not match.")
            return
        data = st.session_state.data
        if username in data['users']:
            st.error("User already exists.")
            return
        salt = generate_salt()
        pass_hash = pbkdf2_hash(passkey, salt)
        data['users'][username] = {
            'salt': base64.b64encode(salt).decode(),
            'pass_hash': base64.b64encode(pass_hash).decode(),
            'entries': [],
            'failed_attempts': 0,
            'lockout_until': None
        }
        save_data(data)
        st.success("Account created. Please log in.")


def login():
    st.header("🔓 Login")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    if st.button("Login"):
        data = st.session_state.data
        user = data['users'].get(username)
        if not user:
            st.error("User not found.")
            return
        # Check lockout
        lockout = user.get('lockout_until')
        if lockout:
            until = datetime.fromisoformat(lockout)
            if until > datetime.utcnow():
                remaining = (until - datetime.utcnow()).seconds // 60
                st.warning(f"Account locked. Try again in {remaining} minute(s).")
                return
            else:
                user['failed_attempts'] = 0
                user['lockout_until'] = None
        # Verify passkey
        salt = base64.b64decode(user['salt'])
        hashed = pbkdf2_hash(passkey, salt)
        if hashed != base64.b64decode(user['pass_hash']):
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= 3:
                user['lockout_until'] = (datetime.utcnow() + LOCKOUT_DURATION).isoformat()
                st.error("Too many attempts. Account locked for 5 minutes.")
            else:
                st.error(f"Incorrect passkey. Attempts: {user['failed_attempts']}/3")
            save_data(data)
            return
        # Success
        st.session_state.authenticated = True
        st.session_state.user = username
        user['failed_attempts'] = 0
        user['lockout_until'] = None
        save_data(data)
        st.success("Logged in successfully.")


def home_page():
    st.title("🏠 Secure Data Encryption App")
    choice = st.radio("Go to:", ["Insert Data", "Retrieve Data", "Logout"])
    if choice == "Insert Data":
        insert_data()
    elif choice == "Retrieve Data":
        retrieve_data()
    else:
        st.session_state.authenticated = False
        st.session_state.user = None
        st.experimental_rerun()


def insert_data():
    st.header("📥 Insert Data")
    raw = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Your passkey", type="password")
    if st.button("Store Securely"):
        if not raw or not passkey:
            st.error("Fill all fields.")
            return
        data = st.session_state.data
        user = data['users'][st.session_state.user]
        # verify passkey
        salt_user = base64.b64decode(user['salt'])
        if pbkdf2_hash(passkey, salt_user) != base64.b64decode(user['pass_hash']):
            st.error("Passkey incorrect.")
            return
        # encrypt
        salt = generate_salt()
        fkey = derive_fernet_key(passkey, salt)
        token = Fernet(fkey).encrypt(raw.encode())
        entry = {
            'id': str(uuid.uuid4()),
            'encrypted_text': token.decode(),
            'salt': base64.b64encode(salt).decode()
        }
        user['entries'].append(entry)
        save_data(data)
        st.success("Data encrypted and stored.")


def retrieve_data():
    st.header("📂 Retrieve Data")
    user = st.session_state.data['users'][st.session_state.user]
    if not user['entries']:
        st.info("No data stored yet.")
        return
    passkey = st.text_input("Your passkey", type="password")
    if st.button("Decrypt All Data"):
        # verify passkey
        salt_user = base64.b64decode(user['salt'])
        if pbkdf2_hash(passkey, salt_user) != base64.b64decode(user['pass_hash']):
            user['failed_attempts'] += 1
            save_data(st.session_state.data)
            if user['failed_attempts'] >= 3:
                user['lockout_until'] = (datetime.utcnow() + LOCKOUT_DURATION).isoformat()
                save_data(st.session_state.data)
                st.error("Too many failed attempts. Please login again.")
                st.session_state.authenticated = False
                st.experimental_rerun()
            else:
                st.error(f"Incorrect passkey. Attempts: {user['failed_attempts']}/3")
            return
        # correct passkey
        user['failed_attempts'] = 0
        save_data(st.session_state.data)
        for entry in user['entries']:
            salt = base64.b64decode(entry['salt'])
            fkey = derive_fernet_key(passkey, salt)
            try:
                text = Fernet(fkey).decrypt(entry['encrypted_text'].encode()).decode()
            except:
                text = "<decryption failed>"
            st.markdown(f"**ID:** {entry['id']}  \n**Data:** {text}")
            st.markdown("---")


# --- App Router ---
if not st.session_state.authenticated:
    page = st.sidebar.selectbox("Welcome", ["Login", "Sign Up"])
    if page == "Login":
        login()
    else:
        signup()
else:
    home_page()
