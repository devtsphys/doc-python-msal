# # Python MSAL Complete Reference Guide

## Overview

Microsoft Authentication Library (MSAL) for Python provides authentication for Microsoft Identity platform applications. It supports various authentication flows and scenarios for both public and confidential client applications.

## Installation

```bash
pip install msal
pip install msal[broker]  # For broker support (Windows/macOS)
```

## Core Classes & Components

### 1. PublicClientApplication

For applications that cannot securely store credentials (mobile apps, desktop apps).

```python
from msal import PublicClientApplication

app = PublicClientApplication(
    client_id="your-client-id",
    authority="https://login.microsoftonline.com/common",  # or tenant-specific
    # Optional parameters
    token_cache=None,
    http_client=None,
    verify=True,
    proxies=None,
    timeout=None
)
```

### 2. ConfidentialClientApplication

For applications that can securely store credentials (web apps, APIs, services).

```python
from msal import ConfidentialClientApplication

app = ConfidentialClientApplication(
    client_id="your-client-id",
    client_credential="your-client-secret",  # or certificate
    authority="https://login.microsoftonline.com/common",
    # Optional parameters
    token_cache=None,
    http_client=None,
    verify=True,
    proxies=None,
    timeout=None
)
```

## Authentication Flows

### 1. Interactive Authentication (Public Client)

```python
# Device Code Flow
result = app.acquire_token_interactive(
    scopes=["User.Read"],
    parent_window_handle=None,  # For desktop apps
    login_hint="user@domain.com",
    domain_hint="contoso.com",
    prompt="select_account",  # none, login, select_account, consent
    extra_scopes_to_consent=["Mail.Read"]
)

# Device Code Flow
flow = app.initiate_device_flow(scopes=["User.Read"])
print(flow["message"])  # Display to user
result = app.acquire_token_by_device_flow(flow)
```

### 2. Username/Password Authentication

```python
result = app.acquire_token_by_username_password(
    username="user@domain.com",
    password="password",
    scopes=["User.Read"]
)
```

### 3. Silent Authentication (Token Cache)

```python
accounts = app.get_accounts()
if accounts:
    result = app.acquire_token_silent(
        scopes=["User.Read"],
        account=accounts[0]  # or specific account
    )
```

### 4. Client Credentials Flow (Confidential Client)

```python
result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
```

### 5. Authorization Code Flow (Web Apps)

```python
# Step 1: Get authorization URL
auth_url = app.get_authorization_request_url(
    scopes=["User.Read"],
    redirect_uri="http://localhost:5000/callback",
    state="random-state-value"
)

# Step 2: Exchange code for token
result = app.acquire_token_by_authorization_code(
    code="authorization-code-from-callback",
    scopes=["User.Read"],
    redirect_uri="http://localhost:5000/callback"
)
```

### 6. On-Behalf-Of Flow

```python
result = app.acquire_token_on_behalf_of(
    user_assertion="jwt-token-from-client",
    scopes=["https://graph.microsoft.com/User.Read"]
)
```

## Complete Function Reference Table

|Class                            |Method                                 |Parameters                                                                                                                                                           |Description                   |Example                                                                |
|---------------------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|-----------------------------------------------------------------------|
|**PublicClientApplication**      |                                       |                                                                                                                                                                     |                              |                                                                       |
|                                 |`__init__()`                           |`client_id, authority, token_cache, http_client, verify, proxies, timeout`                                                                                           |Initialize public client      |`PublicClientApplication("client-id")`                                 |
|                                 |`acquire_token_interactive()`          |`scopes, parent_window_handle, login_hint, domain_hint, prompt, extra_scopes_to_consent`                                                                             |Interactive authentication    |`app.acquire_token_interactive(["User.Read"])`                         |
|                                 |`acquire_token_by_username_password()` |`username, password, scopes`                                                                                                                                         |Username/password auth        |`app.acquire_token_by_username_password("user", "pass", ["User.Read"])`|
|                                 |`acquire_token_silent()`               |`scopes, account, authority, force_refresh, claims_challenge`                                                                                                        |Silent token acquisition      |`app.acquire_token_silent(["User.Read"], accounts[0])`                 |
|                                 |`initiate_device_flow()`               |`scopes, claims_challenge`                                                                                                                                           |Start device flow             |`flow = app.initiate_device_flow(["User.Read"])`                       |
|                                 |`acquire_token_by_device_flow()`       |`flow, claims_challenge`                                                                                                                                             |Complete device flow          |`app.acquire_token_by_device_flow(flow)`                               |
|                                 |`get_accounts()`                       |`username`                                                                                                                                                           |Get cached accounts           |`accounts = app.get_accounts()`                                        |
|                                 |`remove_account()`                     |`account`                                                                                                                                                            |Remove account from cache     |`app.remove_account(account)`                                          |
|**ConfidentialClientApplication**|                                       |                                                                                                                                                                     |                              |                                                                       |
|                                 |`__init__()`                           |`client_id, client_credential, authority, token_cache, http_client, verify, proxies, timeout`                                                                        |Initialize confidential client|`ConfidentialClientApplication("id", "secret")`                        |
|                                 |`acquire_token_for_client()`           |`scopes, claims_challenge`                                                                                                                                           |Client credentials flow       |`app.acquire_token_for_client([".default"])`                           |
|                                 |`acquire_token_by_authorization_code()`|`code, scopes, redirect_uri, nonce, claims_challenge`                                                                                                                |Auth code exchange            |`app.acquire_token_by_authorization_code("code", ["User.Read"])`       |
|                                 |`acquire_token_on_behalf_of()`         |`user_assertion, scopes, claims_challenge`                                                                                                                           |On-behalf-of flow             |`app.acquire_token_on_behalf_of("jwt", ["User.Read"])`                 |
|                                 |`get_authorization_request_url()`      |`scopes, login_hint, state, redirect_uri, nonce, domain_hint, prompt, response_mode, response_type, max_age, ui_locales, id_token_hint, acr_values, claims_challenge`|Generate auth URL             |`app.get_authorization_request_url(["User.Read"])`                     |
|**Common Methods**               |                                       |                                                                                                                                                                     |                              |                                                                       |
|                                 |`acquire_token_silent()`               |`scopes, account, authority, force_refresh, claims_challenge`                                                                                                        |Silent acquisition            |`app.acquire_token_silent(scopes, account)`                            |
|                                 |`get_accounts()`                       |`username`                                                                                                                                                           |List accounts                 |`app.get_accounts()`                                                   |
|                                 |`remove_account()`                     |`account`                                                                                                                                                            |Remove from cache             |`app.remove_account(account)`                                          |

## Token Cache Management

### Basic Token Cache

```python
from msal import TokenCache

# In-memory cache (default)
cache = TokenCache()

# Persistent cache
import atexit
cache = TokenCache()
if os.path.exists("token_cache.bin"):
    cache.deserialize(open("token_cache.bin", "r").read())
atexit.register(lambda: open("token_cache.bin", "w").write(cache.serialize()) if cache.has_state_changed else None)

app = PublicClientApplication("client-id", token_cache=cache)
```

### Advanced Token Cache with Encryption

```python
import msal
import json
from cryptography.fernet import Fernet

class EncryptedTokenCache(msal.TokenCache):
    def __init__(self, cache_file="token_cache.bin"):
        super().__init__()
        self.cache_file = cache_file
        self.key = Fernet.generate_key()  # In production, store securely
        self.cipher = Fernet(self.key)
        
    def load(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'rb') as f:
                encrypted_data = f.read()
                decrypted_data = self.cipher.decrypt(encrypted_data)
                self.deserialize(decrypted_data.decode())
    
    def save(self):
        if self.has_state_changed:
            encrypted_data = self.cipher.encrypt(self.serialize().encode())
            with open(self.cache_file, 'wb') as f:
                f.write(encrypted_data)
```

## Advanced Configuration Examples

### 1. Certificate-Based Authentication

```python
from msal import ConfidentialClientApplication

# Using certificate file
app = ConfidentialClientApplication(
    client_id="your-client-id",
    client_credential={
        "private_key": open("private_key.pem").read(),
        "thumbprint": "certificate-thumbprint",
        # Optional: "public_certificate": "certificate-chain"
    },
    authority="https://login.microsoftonline.com/tenant-id"
)

# Using certificate from store (Windows)
app = ConfidentialClientApplication(
    client_id="your-client-id",
    client_credential={
        "private_key_path": "cert:\\CurrentUser\\My\\thumbprint",
        "thumbprint": "certificate-thumbprint"
    }
)
```

### 2. Custom HTTP Client Configuration

```python
import requests
from msal import PublicClientApplication

session = requests.Session()
session.proxies = {'https': 'http://proxy:8080'}
session.verify = '/path/to/ca-bundle.crt'
session.timeout = 30

app = PublicClientApplication(
    client_id="client-id",
    http_client=session
)
```

### 3. Multi-Tenant Application

```python
# Common authority for multi-tenant
app = PublicClientApplication(
    client_id="client-id",
    authority="https://login.microsoftonline.com/common"
)

# Tenant-specific authority
app = PublicClientApplication(
    client_id="client-id",
    authority="https://login.microsoftonline.com/tenant-id"
)

# Custom authority (B2C)
app = PublicClientApplication(
    client_id="client-id",
    authority="https://tenant.b2clogin.com/tenant.onmicrosoft.com/policy-name"
)
```

## Error Handling Patterns

### Standard Error Handling

```python
def safe_acquire_token(app, scopes, account=None):
    try:
        if account:
            result = app.acquire_token_silent(scopes, account)
            if "access_token" in result:
                return result
        
        # Fall back to interactive
        result = app.acquire_token_interactive(scopes)
        
        if "access_token" in result:
            return result
        elif "error" in result:
            print(f"Error: {result['error']}")
            print(f"Description: {result.get('error_description', '')}")
            if result.get("correlation_id"):
                print(f"Correlation ID: {result['correlation_id']}")
        
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return None
    
    return None
```

### Retry Logic for Transient Errors

```python
import time
import random

def acquire_token_with_retry(app, scopes, max_retries=3):
    for attempt in range(max_retries):
        try:
            result = app.acquire_token_for_client(scopes)
            
            if "access_token" in result:
                return result
            
            # Check for retryable errors
            if result.get("error") in ["temporarily_unavailable", "service_unavailable"]:
                if attempt < max_retries - 1:
                    delay = (2 ** attempt) + random.uniform(0, 1)  # Exponential backoff
                    time.sleep(delay)
                    continue
            
            return result  # Non-retryable error
            
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            raise e
    
    return {"error": "max_retries_exceeded"}
```

## Real-World Usage Patterns

### 1. Web Application with Session Management

```python
from flask import Flask, session, request, redirect, url_for
import msal

app = Flask(__name__)
app.secret_key = "your-secret-key"

def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

@app.route("/login")
def login():
    cache = _load_cache()
    msal_app = ConfidentialClientApplication(
        CLIENT_ID, 
        client_credential=CLIENT_SECRET,
        token_cache=cache
    )
    
    auth_url = msal_app.get_authorization_request_url(
        SCOPES,
        redirect_uri=url_for("authorized", _external=True),
        state=session.get("state", str(uuid.uuid4()))
    )
    
    session["state"] = auth_url.split("state=")[1].split("&")[0]
    return redirect(auth_url)

@app.route("/callback")
def authorized():
    cache = _load_cache()
    msal_app = ConfidentialClientApplication(
        CLIENT_ID,
        client_credential=CLIENT_SECRET,
        token_cache=cache
    )
    
    result = msal_app.acquire_token_by_authorization_code(
        request.args.get('code'),
        scopes=SCOPES,
        redirect_uri=url_for("authorized", _external=True)
    )
    
    _save_cache(cache)
    
    if "access_token" in result:
        session["user"] = result.get("id_token_claims")
        return redirect(url_for("index"))
    else:
        return "Login failed"
```

### 2. Background Service with Client Credentials

```python
import msal
import requests
import schedule
import time

class GraphService:
    def __init__(self, client_id, client_secret, tenant_id):
        self.app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}"
        )
        self.scopes = ["https://graph.microsoft.com/.default"]
        self.token = None
        self.token_expires = 0
    
    def get_access_token(self):
        if not self.token or time.time() >= self.token_expires:
            result = self.app.acquire_token_for_client(scopes=self.scopes)
            
            if "access_token" in result:
                self.token = result["access_token"]
                self.token_expires = time.time() + result.get("expires_in", 3600) - 300  # 5min buffer
            else:
                raise Exception(f"Token acquisition failed: {result.get('error_description')}")
        
        return self.token
    
    def make_graph_call(self, endpoint):
        token = self.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"https://graph.microsoft.com/v1.0/{endpoint}", headers=headers)
        return response.json()
    
    def sync_users(self):
        try:
            users = self.make_graph_call("users?$select=displayName,mail,userPrincipalName")
            # Process users...
            print(f"Synced {len(users.get('value', []))} users")
        except Exception as e:
            print(f"Sync failed: {str(e)}")

# Usage
service = GraphService("client-id", "client-secret", "tenant-id")
schedule.every(30).minutes.do(service.sync_users)

while True:
    schedule.run_pending()
    time.sleep(60)
```

### 3. Desktop Application with Device Code Flow

```python
import msal
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
import webbrowser

class DesktopAuthApp:
    def __init__(self):
        self.app = msal.PublicClientApplication(
            client_id="client-id",
            authority="https://login.microsoftonline.com/common"
        )
        self.token = None
        self.setup_ui()
    
    def setup_ui(self):
        self.root = tk.Tk()
        self.root.title("MSAL Desktop Demo")
        self.root.geometry("500x400")
        
        tk.Button(self.root, text="Login with Device Code", command=self.device_code_login).pack(pady=10)
        tk.Button(self.root, text="Login Interactive", command=self.interactive_login).pack(pady=10)
        tk.Button(self.root, text="Call Graph API", command=self.call_graph).pack(pady=10)
        
        self.output = scrolledtext.ScrolledText(self.root, height=15)
        self.output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    
    def log_message(self, message):
        self.output.insert(tk.END, f"{message}\n")
        self.output.see(tk.END)
        self.root.update()
    
    def device_code_login(self):
        def login_thread():
            try:
                flow = self.app.initiate_device_flow(scopes=["User.Read"])
                self.log_message(flow["message"])
                
                result = self.app.acquire_token_by_device_flow(flow)
                if "access_token" in result:
                    self.token = result["access_token"]
                    self.log_message("✓ Login successful!")
                else:
                    self.log_message(f"✗ Login failed: {result.get('error_description')}")
            except Exception as e:
                self.log_message(f"✗ Exception: {str(e)}")
        
        threading.Thread(target=login_thread, daemon=True).start()
    
    def interactive_login(self):
        try:
            result = self.app.acquire_token_interactive(scopes=["User.Read"])
            if "access_token" in result:
                self.token = result["access_token"]
                self.log_message("✓ Interactive login successful!")
            else:
                self.log_message(f"✗ Interactive login failed: {result.get('error_description')}")
        except Exception as e:
            self.log_message(f"✗ Exception: {str(e)}")
    
    def call_graph(self):
        if not self.token:
            messagebox.showwarning("Warning", "Please login first!")
            return
        
        try:
            import requests
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            
            if response.status_code == 200:
                user_info = response.json()
                self.log_message(f"✓ Hello {user_info.get('displayName', 'User')}!")
                self.log_message(f"Email: {user_info.get('mail', 'N/A')}")
            else:
                self.log_message(f"✗ Graph API call failed: {response.status_code}")
        except Exception as e:
            self.log_message(f"✗ Exception: {str(e)}")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DesktopAuthApp()
    app.run()
```

## Best Practices & Tips

### Security Best Practices

1. **Never expose client secrets** in client-side code
1. **Use PKCE** for public clients when possible
1. **Implement proper token storage** with encryption for sensitive applications
1. **Validate tokens** on the server side
1. **Use specific scopes** rather than broad permissions
1. **Implement token refresh** logic properly

### Performance Optimization

1. **Cache tokens** appropriately to avoid unnecessary API calls
1. **Use silent authentication** first before falling back to interactive
1. **Implement connection pooling** for high-volume applications
1. **Handle rate limiting** with exponential backoff
1. **Use async patterns** for I/O-bound operations

### Debugging & Troubleshooting

```python
import logging
import msal

# Enable MSAL logging
logging.basicConfig(level=logging.DEBUG)
msal_logger = logging.getLogger("msal")
msal_logger.setLevel(logging.INFO)

# Add correlation ID tracking
def track_request(result):
    if "correlation_id" in result:
        print(f"Correlation ID: {result['correlation_id']}")
    return result
```

## Common Error Scenarios & Solutions

|Error                |Cause                |Solution                                    |
|---------------------|---------------------|--------------------------------------------|
|`AADSTS50011`        |Invalid redirect URI |Ensure redirect URI matches app registration|
|`AADSTS50020`        |User not found       |Check user exists in tenant                 |
|`AADSTS65001`        |User consent required|Add consent prompt or pre-consent           |
|`AADSTS70011`        |Invalid scope        |Verify scope format and permissions         |
|`AADSTS700016`       |Invalid client ID    |Check client ID in app registration         |
|`AADSTS7000215`      |Invalid client secret|Verify client secret hasn’t expired         |
|`TokenNotFound`      |No cached token      |Implement fallback authentication           |
|`InteractionRequired`|Silent auth failed   |Use interactive authentication              |

This reference guide covers the essential and advanced features of Python MSAL, providing both theoretical knowledge and practical implementation examples for various authentication scenarios.