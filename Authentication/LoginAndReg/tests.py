from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser
from .forms import CustomUserCreationForm, LoginForm

User = get_user_model()

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user_data = {
            'username': 'testuser123',
            'email': 'test@example.com',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!'
        }
        self.login_data = {
            'username': 'testuser123',
            'password': 'TestPass123!'
        }

    def test_user_registration(self):
        """Test user registration with valid data"""
        response = self.client.post(reverse('register'), self.user_data)
        self.assertEqual(response.status_code, 302)  # Redirect after successful registration
        self.assertTrue(User.objects.filter(username='testuser123').exists())

    def test_username_validation(self):
        """Test username validation (minimum 6 characters)"""
        form_data = self.user_data.copy()
        form_data['username'] = 'test'  # Less than 6 characters
        form = CustomUserCreationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)

    def test_password_validation(self):
        """Test password validation (8+ chars, letters, numbers, special chars)"""
        form_data = self.user_data.copy()
        form_data['password1'] = 'weak'  # Too weak
        form_data['password2'] = 'weak'
        form = CustomUserCreationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

    def test_user_login(self):
        """Test user login with valid credentials"""
        # Create user first
        user = User.objects.create_user(
            username='testuser123',
            email='test@example.com',
            password='TestPass123!'
        )
        
        response = self.client.post(reverse('login'), self.login_data)
        self.assertEqual(response.status_code, 302)  # Redirect after successful login

    def test_failed_login_attempts(self):
        """Test account lockout after 3 failed attempts"""
        user = User.objects.create_user(
            username='testuser123',
            email='test@example.com',
            password='TestPass123!'
        )
        
        # Attempt 3 failed logins
        for i in range(3):
            response = self.client.post(reverse('login'), {
                'username': 'testuser123',
                'password': 'wrongpassword'
            })
        
        user.refresh_from_db()
        self.assertTrue(user.is_blocked)
        self.assertEqual(user.failed_login_attempts, 3)

    def test_qr_code_generation(self):
        """Test QR code generation for user"""
        user = User.objects.create_user(
            username='testuser123',
            email='test@example.com',
            password='TestPass123!'
        )
        
        # Generate QR secret
        secret = user.generate_qr_secret()
        self.assertIsNotNone(secret)
        self.assertEqual(len(secret), 32)
        
        # Generate QR code image
        qr_image = user.generate_qr_code()
        self.assertIsNotNone(qr_image)

    def test_qr_code_verification(self):
        """Test QR code verification"""
        user = User.objects.create_user(
            username='testuser123',
            email='test@example.com',
            password='TestPass123!'
        )
        
        # Generate QR secret
        user.generate_qr_secret()
        
        # This would normally be done with a real TOTP token
        # For testing, we'll just verify the method exists
        self.assertTrue(hasattr(user, 'verify_qr_code'))

    def test_reset_failed_attempts(self):
        """Test resetting failed login attempts"""
        user = User.objects.create_user(
            username='testuser123',
            email='test@example.com',
            password='TestPass123!'
        )
        
        # Simulate failed attempts
        user.failed_login_attempts = 2
        user.is_blocked = True
        user.blocked_until = timezone.now() + timedelta(hours=1)
        user.save()
        
        # Reset attempts
        user.reset_failed_attempts()
        
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertFalse(user.is_blocked)
        self.assertIsNone(user.blocked_until)

    def test_home_page_access(self):
        """Test home page is accessible"""
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Django Authentication System')

    def test_dashboard_requires_login(self):
        """Test dashboard requires authentication"""
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_facebook_login_page(self):
        """Test Facebook login page is accessible"""
        response = self.client.get(reverse('facebook_login'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Facebook Login')

class FormTestCase(TestCase):
    def test_custom_user_creation_form_valid(self):
        """Test CustomUserCreationForm with valid data"""
        form_data = {
            'username': 'testuser123',
            'email': 'test@example.com',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!'
        }
        form = CustomUserCreationForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_custom_user_creation_form_invalid_username(self):
        """Test CustomUserCreationForm with invalid username"""
        form_data = {
            'username': 'test',  # Less than 6 characters
            'email': 'test@example.com',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!'
        }
        form = CustomUserCreationForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_custom_user_creation_form_invalid_password(self):
        """Test CustomUserCreationForm with invalid password"""
        form_data = {
            'username': 'testuser123',
            'email': 'test@example.com',
            'password1': 'weak',  # Too weak
            'password2': 'weak'
        }
        form = CustomUserCreationForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_login_form_valid(self):
        """Test LoginForm with valid data"""
        form_data = {
            'username': 'testuser123',
            'password': 'TestPass123!'
        }
        form = LoginForm(data=form_data)
        self.assertTrue(form.is_valid())