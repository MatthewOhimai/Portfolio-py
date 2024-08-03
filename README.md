Let's create a comprehensive guide on building an E-commerce site using Flask (Python) along with OAuth authentication, and login/registration features, including source code examples.

### E-commerce Site with Flask, OAuth, and User Authentication

#### Table of Contents
1. Introduction
2. Setting Up the Flask Environment
3. Building the E-commerce Site
4. Implementing OAuth Authentication
5. Adding User Login and Registration
6. Complete Source Code

### 1. Introduction

This tutorial will walk you through building an e-commerce site using Flask, integrating OAuth for authentication with Google, and adding user login and registration features using MySQL for the database.

### 2. Setting Up the Flask Environment

First, we need to set up our Flask environment. We'll create a virtual environment and install Flask and other dependencies.

**Install Flask:**
```sh
pip install flask
pip install flask_sqlalchemy
pip install flask_login
pip install requests
```

### 3. Building the E-commerce Site

Let's start with the basic structure of our Flask application.

**Directory Structure:**
```
ecommerce_site/
    ├── app.py
    ├── templates/
    │   ├── home.html
    │   ├── login.html
    │   ├── register.html
    │   ├── dashboard.html
    ├── static/
    │   ├── styles.css
    ├── models.py
    ├── oauth.py
    └── config.py
```

**app.py:**
```python
from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from oauth import OAuthSignIn

app = Flask(__name__)
app.config.from_object('config')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()

@app.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email = oauth.callback()
    if social_id is None:
        return redirect(url_for('index'))
    user = User.query.filter_by(social_id=social_id).first()
    if not user:
        user = User(social_id=social_id, username=username, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
```

**config.py:**
```python
import os

basedir = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = 'this-is-a-secret-key'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

OAUTH_CREDENTIALS = {
    'google': {
        'id': 'your-google-client-id',
        'secret': 'your-google-client-secret'
    }
}
```

**models.py:**
```python
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(64), nullable=False, unique=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False, unique=True)
```

**oauth.py:**
```python
import json
from rauth import OAuth2Service
from flask import current_app, url_for, request, redirect, session

class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name, _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]

class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
            name='google',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            base_url='https://www.googleapis.com/oauth2/v1/',
            access_token_url='https://accounts.google.com/o/oauth2/token'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=decode_json
        )
        me = oauth_session.get('userinfo').json()
        return (
            'google$' + me['id'],
            me['name'],
            me['email']
        )
```

**templates/home.html:**
```html
<!doctype html>
<html>
<head>
    <title>Home</title>
</head>
<body>
    <h1>Welcome to the E-commerce Site</h1>
    {% if current_user.is_authenticated %}
        <p>Hello, {{ current_user.username }}!</p>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
</body>
</html>
```

**templates/login.html:**
```html
<!doctype html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <a href="{{ url_for('oauth_authorize', provider='google') }}">Login with Google</a>
</body>
</html>
```

### 4. Implementing OAuth Authentication

The OAuth implementation in the `oauth.py` file handles authentication with Google. Adjust the `config.py` file with your own OAuth credentials.

### 5. Adding User Login and Registration

**templates/register.html:**
```html
<!doctype html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h1>Register</h1>
    <form method="post" action="{{ url_for('register') }}">
        <label for="username">Username:</label>
        <input type="text" name="username" id="username">
        <label for="email">Email:</label>
        <input type="email" name="email" id="email">
        <label for="password">Password:</label>
        <input type="password" name="password" id="password">
        <button type="submit">Register</button>
    </form>
</body>
</html>
```

**Update app.py:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, email=email, password_hash=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
```

### 6. Complete Source Code

Combining everything, your Flask application will have:
- OAuth authentication with Google
- User login and registration with email/password
- A basic home page for authenticated users

### Final Notes

This guide provides a comprehensive example of setting up an e-commerce site with user authentication using Flask. Adjustments can be made to extend the site's functionality, such as adding product listings, cart functionality, payment integration, and more sophisticated UI/UX designs.

Feel free to ask if you need more specific features or deeper insights into any part of the implementation

!Let's create a comprehensive guide on building an E-commerce site using Flask (Python) along with OAuth authentication, and login/registration features, including source code examples.

### E-commerce Site with Flask, OAuth, and User Authentication

#### Table of Contents
1. Introduction
2. Setting Up the Flask Environment
3. Building the E-commerce Site
4. Implementing OAuth Authentication
5. Adding User Login and Registration
6. Complete Source Code

### 1. Introduction

This tutorial will walk you through building an e-commerce site using Flask, integrating OAuth for authentication with Google, and adding user login and registration features using MySQL for the database.

### 2. Setting Up the Flask Environment

First, we need to set up our Flask environment. We'll create a virtual environment and install Flask and other dependencies.

**Install Flask:**
```sh
pip install flask
pip install flask_sqlalchemy
pip install flask_login
pip install requests
```

### 3. Building the E-commerce Site

Let's start with the basic structure of our Flask application.

**Directory Structure:**
```
ecommerce_site/
    ├── app.py
    ├── templates/
    │   ├── home.html
    │   ├── login.html
    │   ├── register.html
    │   ├── dashboard.html
    ├── static/
    │   ├── styles.css
    ├── models.py
    ├── oauth.py
    └── config.py
```

**app.py:**
```python
from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from oauth import OAuthSignIn

app = Flask(__name__)
app.config.from_object('config')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()

@app.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email = oauth.callback()
    if social_id is None:
        return redirect(url_for('index'))
    user = User.query.filter_by(social_id=social_id).first()
    if not user:
        user = User(social_id=social_id, username=username, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
```

**config.py:**
```python
import os

basedir = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = 'this-is-a-secret-key'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

OAUTH_CREDENTIALS = {
    'google': {
        'id': 'your-google-client-id',
        'secret': 'your-google-client-secret'
    }
}
```

**models.py:**
```python
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(64), nullable=False, unique=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False, unique=True)
```

**oauth.py:**
```python
import json
from rauth import OAuth2Service
from flask import current_app, url_for, request, redirect, session

class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name, _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]

class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
            name='google',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            base_url='https://www.googleapis.com/oauth2/v1/',
            access_token_url='https://accounts.google.com/o/oauth2/token'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=decode_json
        )
        me = oauth_session.get('userinfo').json()
        return (
            'google$' + me['id'],
            me['name'],
            me['email']
        )
```

**templates/home.html:**
```html
<!doctype html>
<html>
<head>
    <title>Home</title>
</head>
<body>
    <h1>Welcome to the E-commerce Site</h1>
    {% if current_user.is_authenticated %}
        <p>Hello, {{ current_user.username }}!</p>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
</body>
</html>
```

**templates/login.html:**
```html
<!doctype html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <a href="{{ url_for('oauth_authorize', provider='google') }}">Login with Google</a>
</body>
</html>
```

### 4. Implementing OAuth Authentication

The OAuth implementation in the `oauth.py` file handles authentication with Google. Adjust the `config.py` file with your own OAuth credentials.

### 5. Adding User Login and Registration

**templates/register.html:**
```html
<!doctype html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h1>Register</h1>
    <form method="post" action="{{ url_for('register') }}">
        <label for="username">Username:</label>
        <input type="text" name="username" id="username">
        <label for="email">Email:</label>
        <input type="email" name="email" id="email">
        <label for="password">Password:</label>
        <input type="password" name="password" id="password">
        <button type="submit">Register</button>
    </form>
</body>
</html>
```

**Update app.py:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, email=email, password_hash=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
```

### 6. Complete Source Code

Combining everything, your Flask application will have:
- OAuth authentication with Google
- User login and registration with email/password
- A basic home page for authenticated users

### Final Notes

This guide provides a comprehensive example of setting up an e-commerce site with user authentication using Flask. Adjustments can be made to extend the site's functionality, such as adding product listings, cart functionality, payment integration, and more sophisticated UI/UX designs.

Feel free to ask if you need more specific features or deeper insights into any part of the implementation

!
