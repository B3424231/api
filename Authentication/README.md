# Django Authentication System

A comprehensive Django authentication system with multiple authentication methods including traditional login/registration, QR code authentication (Google Authenticator), and Facebook authentication.

## Features

### 🔐 Core Authentication
- **User Registration**: Username (6+ characters) and password (8+ characters with letters, numbers, and special characters)
- **User Login**: Traditional username/password authentication
- **Account Lockout**: Users are blocked after 3 failed login attempts for 1 hour
- **Password Validation**: Strong password requirements enforced

### 🔑 Multi-Factor Authentication
- **QR Code Authentication**: Integration with Google Authenticator
- **TOTP (Time-based One-Time Password)**: Secure 6-digit codes
- **Optional 2FA**: Users can enable/disable QR code authentication

### 📱 Social Authentication
- **Facebook Login**: Demo implementation with Facebook SDK integration
- **Social Account Linking**: Link Facebook accounts to existing users

### 🛡️ Security Features
- **Custom User Model**: Extended Django user model with additional security fields
- **Failed Attempt Tracking**: Monitor and limit login attempts
- **Account Blocking**: Temporary account suspension after multiple failures
- **CSRF Protection**: Built-in Django CSRF protection

## Installation

### Prerequisites
- Python 3.8+
- Django 5.2.6
- pip

### Setup Instructions

1. **Clone or navigate to the project directory:**
   ```bash
   cd Authentication
   ```

2. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run database migrations:**
   ```bash
   python manage.py migrate
   ```

4. **Create a superuser (optional):**
   ```bash
   python manage.py createsuperuser
   ```

5. **Start the development server:**
   ```bash
   python manage.py runserver
   ```

6. **Access the application:**
   - Open your browser and go to `http://127.0.0.1:8000/`
   - Admin panel: `http://127.0.0.1:8000/admin/`

## Usage

### Registration
1. Click "Register" on the home page
2. Enter username (minimum 6 characters)
3. Enter email address
4. Create password (minimum 8 characters with letters, numbers, and special characters)
5. Confirm password
6. Click "Register"

### Login
1. Click "Login" on the home page
2. Enter username and password
3. If QR code authentication is enabled, enter the 6-digit code from Google Authenticator
4. Click "Login"

### Setting up QR Code Authentication
1. Login to your account
2. Go to Dashboard
3. Click "Setup QR Code" in the QR Code Authentication section
4. Install Google Authenticator app on your mobile device
5. Scan the QR code displayed on the screen
6. Enter the 6-digit verification code from the app
7. Click "Enable QR Code Authentication"

### Facebook Authentication (Demo)
1. Click "Login with Facebook" on the home page
2. In the demo modal, enter your email and name
3. Click "Login with Facebook"
4. You'll be logged in with a demo Facebook account

## Project Structure

```
Authentication/
├── Authentication/          # Django project settings
│   ├── __init__.py
│   ├── settings.py         # Project settings
│   ├── urls.py            # Main URL configuration
│   ├── wsgi.py
│   └── asgi.py
├── LoginAndReg/           # Main authentication app
│   ├── models.py          # Custom user model
│   ├── views.py           # Authentication views
│   ├── forms.py           # Form definitions
│   ├── urls.py            # App URL patterns
│   ├── admin.py           # Admin configuration
│   └── templates/         # HTML templates
│       ├── base.html
│       ├── home.html
│       ├── register.html
│       ├── login.html
│       ├── dashboard.html
│       ├── setup_qr.html
│       └── facebook_login.html
├── manage.py              # Django management script
├── requirements.txt       # Python dependencies
├── db.sqlite3            # SQLite database
└── README.md             # This file
```

## API Endpoints

- `/` - Home page
- `/register/` - User registration
- `/login/` - User login
- `/logout/` - User logout
- `/dashboard/` - User dashboard (requires login)
- `/setup-qr/` - QR code setup (requires login)
- `/disable-qr/` - Disable QR code authentication (requires login)
- `/facebook-login/` - Facebook login page
- `/facebook-callback/` - Facebook authentication callback
- `/admin/` - Django admin panel

## Security Considerations

1. **Password Requirements**: Enforced minimum length and complexity
2. **Account Lockout**: Prevents brute force attacks
3. **CSRF Protection**: Built-in Django CSRF middleware
4. **Session Security**: Django's secure session handling
5. **Input Validation**: Server-side validation for all forms
6. **SQL Injection Protection**: Django ORM prevents SQL injection

## Customization

### Adding New Authentication Methods
1. Extend the `CustomUser` model in `models.py`
2. Create new forms in `forms.py`
3. Add views in `views.py`
4. Update URL patterns in `urls.py`
5. Create templates in the `templates/` directory

### Modifying Password Requirements
Edit the `clean_password1` method in `LoginAndReg/forms.py` to change password validation rules.

### Changing Lockout Settings
Modify the `increment_failed_attempts` method in `LoginAndReg/models.py` to change lockout behavior.

## Troubleshooting

### Common Issues

1. **Module not found errors**: Ensure all packages are installed with `pip install -r requirements.txt`
2. **Database errors**: Run `python manage.py migrate` to apply migrations
3. **Static files not loading**: Ensure `DEBUG = True` in settings.py for development
4. **QR code not generating**: Check that Pillow and qrcode packages are installed

### Debug Mode
The application runs in debug mode by default. For production deployment:
1. Set `DEBUG = False` in `settings.py`
2. Configure proper database settings
3. Set up static file serving
4. Configure proper security settings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.

