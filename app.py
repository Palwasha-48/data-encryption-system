import streamlit as st
import hashlib
import time
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Page configuration
st.set_page_config(
    page_title="Secure Data Vault",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS for complete dark red theme - fixing sidebar and all elements
st.markdown("""
<style>
    /* Base page styling */
    .stApp {
        background-color: #121212;
        color: #F0F0F0;
    }
            
    [data-testid=stTextInputRootElement]{
        background-color: #D32F2F !important;        
    }
            
    [type="button"]{
        background-color: #D32F2F !important; 
    }
            
    [data-testid=stBaseButton-secondary]{
        background-color: #D32F2F !important;
        color: white !important;
    }
    
    /* Fix sidebar background */
    .css-1d391kg, .css-1e5imcs, .css-1wrcr25, .css-ocqkz7, .css-uf99v8, 
    .css-ffhzg2, section[data-testid="stSidebar"], .css-6qob1r, .css-1544g2n {
        background-color: #1E1E1E !important;
        color: #F0F0F0 !important;
    }
    
    /* Fix radio buttons and checkboxes */
    .stRadio > div, .stCheckbox > div {
        background-color: transparent !important;
    }
    
    .stRadio label, .stCheckbox label {
        color: #F0F0F0 !important;
    }
    
    /* Fix selectbox */
    .stSelectbox > div > div, .stMultiSelect > div > div {
        background-color: #2D2D2D !important;
        color: #F0F0F0 !important;
    }
    
    /* Fix text inputs and text areas */
    .stTextInput > div > div > input, .stTextArea > div > div > textarea, 
    .stNumberInput > div > div > input {
        background-color: #2D2D2D !important;
        color: #F0F0F0 !important;
        border: 1px solid #444 !important;
    }
            
    .element-container{
        width: 100% !important;        
    }
    
    /* Style for all Streamlit containers */
    .element-container, .stMarkdown, .block-container {
        color: #F0F0F0 !important;
    }
    
    /* Header styling */
    .main-header {
        font-size: 2.5rem !important;
        color: #FF5252 !important;
        text-align: center;
        margin-bottom: 1rem;
        text-shadow: 0px 0px 10px rgba(255, 82, 82, 0.3);
    }
    
    .sub-header {
        font-size: 1.8rem !important;
        color: #FF8A80 !important;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    
    /* Message boxes */
    .success-msg {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #1E3B2F;
        border-left: 0.5rem solid #4CAF50;
        margin: 1rem 0;
        width: 100%;
    }
    
    .error-msg {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #3E2222;
        border-left: 0.5rem solid #F44336;
        margin: 1rem 0;
    }
    
    .warning-msg {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #332500;
        border-left: 0.5rem solid #FFC107;
        margin: 1rem 0;
    }
    
    .info-card {
        padding: 1.5rem;
        border-radius: 0.5rem;
        background-color: #2D2D2D;
        border: 1px solid #3D3D3D;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        margin: 1rem 0;
    }
    
    /* Button styling */
    .stButton > button {
        background-color: #D32F2F !important;
        color: white !important;
        border-radius: 0.5rem !important;
        padding: 0.5rem 1rem !important;
        font-weight: bold !important;
        border: none !important;
        width: 100% !important;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2) !important;
        transition: all 0.3s ease !important;
    }
    
    .stButton > button:hover {
        background-color: #B71C1C !important;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3) !important;
        transform: translateY(-2px) !important;
    }
    
    /* Feature card styling */
    .feature-card {
        background-color: #2D2D2D;
        padding: 1.5rem;
        border-radius: 0.5rem;
        height: auto;
        border: 1px solid #3D3D3D;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        transition: all 0.3s ease;
    }
    
    .feature-card:hover {
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
        transform: translateY(-5px);
    }
    
    /* Navigation sidebar styling */
    .css-1v3fvcr, .css-1544g2n, [data-testid="stSidebar"] {
        background-color: #1E1E1E !important;
    }
    
    /* Footer styling */
    .footer {
        text-align: center;
        color: #888;
        padding: 10px;
        font-size: 0.9rem;
    }
    
    /* Password visibility icon styling */
    .password-container {
        position: relative;
    }
    
    .password-icon {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        cursor: pointer;
        color: #888;
    }
    
    /* Special button effects */
    .main-button {
        background: linear-gradient(45deg, #D32F2F, #FF5252) !important;
        border: none !important;
        color: white !important;
        font-weight: bold !important;
        padding: 12px 20px !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        box-shadow: 0 4px 10px rgba(211, 47, 47, 0.5) !important;
        border-radius: 8px !important;
        transition: all 0.3s !important;
        width: 100% !important;
    }
    
    .main-button:hover {
        transform: translateY(-3px) !important;
        box-shadow: 0 6px 15px rgba(211, 47, 47, 0.6) !important;
    }
    
    /* Fix expander styling */
    .streamlit-expanderHeader {
        background-color: #2D2D2D !important;
        color: #F0F0F0 !important;
    }
    
    /* Fix dataframe styling */
    .stDataFrame {
        background-color: #2D2D2D !important;
    }
    
    .stDataFrame [data-testid="stTable"] {
        background-color: #2D2D2D !important;
        color: #F0F0F0 !important;
    }
    
    /* Remove whitespace at the top */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 1rem !important;
    }
    
    /* Fix dropdown menus */
    div[data-baseweb="select"] > div {
        background-color: #2D2D2D !important;
        color: #F0F0F0 !important;
    }
    
    div[data-baseweb="popover"] > div > div {
        background-color: #2D2D2D !important;
    }
    
    div[role="listbox"] {
        background-color: #2D2D2D !important;
    }
    
    div[role="option"] {
        color: #F0F0F0 !important;
    }
    
    /* Fix slider styling */
    .stSlider [data-baseweb="slider"] {
        background-color: #2D2D2D !important;
    }
    
    /* Style for navigation links */
    .nav-link {
        color: #FF5252 !important;
        text-decoration: none;
        font-weight: bold;
        transition: all 0.3s;
    }
    
    .nav-link:hover {
        color: #FF8A80 !important;
        text-decoration: underline;
    }
    
    /* Visual indicator for current page */
    .active-page {
        border-left: 4px solid #FF5252;
        padding-left: 10px;
        background-color: #2D2D2D !important;
    }

    /* Styling for header icons */
    .icon-header {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables if not present
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = True  # Start as authenticated

if 'last_failed_time' not in st.session_state:
    st.session_state.last_failed_time = 0

if 'current_page' not in st.session_state:
    st.session_state.current_page = "🏠 Home"

if 'key' not in st.session_state:
    # Generate a key (in production, store this securely)
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

# Function to derive key from passkey (PBKDF2)
def derive_key(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Function to hash passkey with PBKDF2 (more secure than SHA-256)
def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac(
        'sha256', 
        passkey.encode(), 
        b'securesalt', 
        100000
    ).hex()

# Function to encrypt data
def encrypt_data(text, passkey):
    key, salt = derive_key(passkey)
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(text.encode()).decode()
    return encrypted_data, salt

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, stored_salt):
    try:
        key, _ = derive_key(passkey, stored_salt)
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_text.encode()).decode()
        return decrypted_data
    except Exception:
        return None

# Function to check passkey
def check_passkey(encrypted_text_id, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    if encrypted_text_id in st.session_state.stored_data:
        if st.session_state.stored_data[encrypted_text_id]["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return True
    
    # Increment failed attempts
    st.session_state.failed_attempts += 1
    st.session_state.last_failed_time = time.time()
    
    # If too many failed attempts, require reauthorization
    if st.session_state.failed_attempts >= 3:
        st.session_state.is_authenticated = False
    
    return False

# Function to save data to session
def save_data(user_data, passkey, data_name):
    hashed_passkey = hash_passkey(passkey)
    encrypted_text, salt = encrypt_data(user_data, passkey)
    data_id = f"{data_name}_{time.time()}"
    
    st.session_state.stored_data[data_id] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey,
        "salt": salt,
        "name": data_name,
        "timestamp": time.time()
    }
    return data_id

# Custom navigation
def custom_sidebar():
    with st.sidebar:
        st.markdown('<div class="icon-header">', unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center; color: #FF5252;'>🔐 Navigation</h2>", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Define menu options
        menu = ["🏠 Home", "📝 Store Data", "🔍 Retrieve Data"]
        
        # Create radio buttons with custom CSS for selected option
        selected_page_index = menu.index(st.session_state.current_page) if st.session_state.current_page in menu else 0
        choice = st.radio("Select an option:", menu, index=selected_page_index)
        
        if choice != st.session_state.current_page:
            st.session_state.current_page = choice
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown('<div class="icon-header">', unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center; color: #FF5252;'>📊 Vault Status</h3>", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Display status information
        st.write(f"📦 Stored items: {len(st.session_state.stored_data)}")
        if st.session_state.failed_attempts > 0:
            st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")
        else:
            st.success("✅ Security status: Good")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    return st.session_state.current_page

# Call custom sidebar
choice = custom_sidebar()

# Login/Reauthorization Page
if not st.session_state.is_authenticated:
    st.markdown("<h1 class='main-header'>🔒 Reauthorization Required</h1>", unsafe_allow_html=True)
    
    # Cooldown timer if applicable
    current_time = time.time()
    time_passed = current_time - st.session_state.last_failed_time
    cooldown_time = 30  # seconds
    
    if time_passed < cooldown_time:
        time_left = int(cooldown_time - time_passed)
        st.markdown(f"""
        <div class='warning-msg'>
            <h3>🕒 Account Temporarily Locked</h3>
            <p>Too many failed attempts. Please wait {time_left} seconds before trying again.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class='info-card'>
            <h3 style="color: #FF5252;">🔐 Security Notice</h3>
            <p>For your security, you need to reauthorize after multiple failed attempts.</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.container():
            login_pass = st.text_input("Enter Master Password:", type="password")
            
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if st.button("🔑 Login", key="login_btn", use_container_width=True):
                    # Using a simple master password for demo (in production, use proper auth)
                    if login_pass == "admin123":
                        st.session_state.failed_attempts = 0
                        st.session_state.is_authenticated = True
                        st.success("✅ Reauthorized successfully!")
                        st.experimental_rerun()
                    else:
                        st.markdown("""
                        <div class='error-msg'>
                            <p>❌ Incorrect password!</p>
                        </div>
                        """, unsafe_allow_html=True)
else:
    # Main App Pages
    if choice == "🏠 Home":
        st.markdown("<h1 class='main-header'>🔐 Secure Data Vault</h1>", unsafe_allow_html=True)
        
        # Animated intro with emojis
        st.markdown("""
        <div class='info-card'>
            <h3 style="color: #FF5252;">👋 Welcome to your Dark Secure Vault</h3>
            <p>Store and retrieve sensitive information with advanced encryption in a sleek, dark interface.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Feature cards with improved styling
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="feature-card">
                <h3 style="color:#FF5252">📝 Store Data</h3>
                <p>Encrypt and store sensitive information with a personal passkey.</p>
                <p>Your data remains protected with advanced PBKDF2 encryption.</p>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown("""
            <div class="feature-card">
                <h3 style="color:#FF5252">🔍 Retrieve Data</h3>
                <p>Access your encrypted information by providing the correct passkey.</p>
                <p>Three failed attempts will trigger security protocols.</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Security features explanation
        st.markdown("<h2 class='sub-header'>🛡️ Security Features</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-card'>
            <ul>
                <li><strong style="color:#FF5252">PBKDF2 Hashing</strong>: More secure than standard SHA-256</li>
                <li><strong style="color:#FF5252">Fernet Encryption</strong>: Military-grade symmetric encryption</li>
                <li><strong style="color:#FF5252">Attempt Limiting</strong>: Prevents brute force attacks</li>
                <li><strong style="color:#FF5252">Memory-Only Storage</strong>: Data not persisted between sessions</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    elif choice == "📝 Store Data":
        st.markdown("<div class='icon-header'>", unsafe_allow_html=True)
        st.markdown("<h1 class='main-header'>📝 Store Encrypted Data</h1>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("""
        <div class='info-card'>
            <p>Enter your sensitive information and a unique passkey to encrypt and store your data securely.</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.container():
            data_name = st.text_input("Data Label:", placeholder="E.g., Personal Notes, Password, etc.")
            user_data = st.text_area("Enter Data:", height=150, placeholder="Type your sensitive information here...")
            
            # Password fields with consistent styling
            passkey = st.text_input("Create Passkey:", type="password", placeholder="Create a strong, memorable passkey")
            confirm_passkey = st.text_input("Confirm Passkey:", type="password", placeholder="Confirm your passkey")
            
            if st.button("🔒 Encrypt & Save", key="encrypt_btn", help="Click to encrypt and save your data", use_container_width=True):
                if not data_name:
                    st.markdown("""
                    <div class='error-msg'>
                        <p>⚠️ Please provide a data label!</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif not user_data:
                    st.markdown("""
                    <div class='error-msg'>
                        <p>⚠️ Please enter some data to encrypt!</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif not passkey:
                    st.markdown("""
                    <div class='error-msg'>
                        <p>⚠️ Please create a passkey!</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif passkey != confirm_passkey:
                    st.markdown("""
                    <div class='error-msg'>
                        <p>⚠️ Passkeys do not match!</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    data_id = save_data(user_data, passkey, data_name)
                    st.markdown(f"""
                    <div class='success-msg'>
                        <h3>✅ Data Stored Successfully!</h3>
                        <p>Your data has been encrypted and stored with ID: <code>{data_id}</code></p>
                        <p><strong>Remember:</strong> Keep your passkey safe. Without it, your data cannot be recovered.</p>
                    </div>
                    """, unsafe_allow_html=True)

    elif choice == "🔍 Retrieve Data":
        st.markdown("<div class='icon-header'>", unsafe_allow_html=True)
        st.markdown("<h1 class='main-header'>🔍 Retrieve Encrypted Data</h1>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
        if len(st.session_state.stored_data) == 0:
            st.markdown("""
            <div class='warning-msg'>
                <h3>📭 No Data Found</h3>
                <p>You haven't stored any encrypted data yet. Please go to the "Store Data" section first.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class='info-card'>
                <p>Select your data item and enter the correct passkey to decrypt it.</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.container():                
                # Create a list of data items with their names
                data_options = {f"{item['name']} ({id.split('_')[0]})": id for id, item in st.session_state.stored_data.items()}
                selected_data_name = st.selectbox("Select data to retrieve:", list(data_options.keys()))
                selected_data_id = data_options[selected_data_name]
                
                passkey = st.text_input("Enter Passkey:", type="password", placeholder="Enter the passkey for this data")
                
                if st.button("🔓 Decrypt Data", key="decrypt_btn", help="Click to decrypt your data", use_container_width=True):
                    if passkey:
                        if check_passkey(selected_data_id, passkey):
                            decrypted_text = decrypt_data(
                                st.session_state.stored_data[selected_data_id]["encrypted_text"],
                                passkey,
                                st.session_state.stored_data[selected_data_id].get("salt", None)
                            )
                            
                            if decrypted_text:
                                st.markdown(f"""
                                <div class='success-msg'>
                                    <h3>✅ Data Retrieved Successfully!</h3>
                                </div>
                                """, unsafe_allow_html=True)

                                st.markdown(f"### Your Decrypted Data: {decrypted_text}")
                            else:
                                st.markdown("""
                                <div class='error-msg'>
                                    <p>❌ Decryption failed. The passkey might be incorrect.</p>
                                </div>
                                """, unsafe_allow_html=True)
                        else:
                            attempts_left = 3 - st.session_state.failed_attempts
                            st.markdown(f"""
                            <div class='error-msg'>
                                <p>❌ Incorrect passkey! Attempts remaining: {attempts_left}</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            if attempts_left <= 0:
                                st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                                st.experimental_rerun()
                    else:
                        st.markdown("""
                        <div class='error-msg'>
                            <p>⚠️ Please enter a passkey!</p>
                        </div>
                        """, unsafe_allow_html=True)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div class='footer'>
        <p>🛡️ Secure Data Vault | Developed with ❤️ using Streamlit | Special credit goes to Muhammad Hamza </p>
    </div>
    """, unsafe_allow_html=True)