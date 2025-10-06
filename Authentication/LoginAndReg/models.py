from django.contrib.auth.models import AbstractUser
from django.db import models
import secrets
import pyotp
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
import base64

class CustomUser(AbstractUser):
    # Additional fields for authentication
    failed_login_attempts = models.IntegerField(default=0)
    is_blocked = models.BooleanField(default=False)
    blocked_until = models.DateTimeField(null=True, blank=True)
    
    # QR Code Authentication
    qr_secret_key = models.CharField(max_length=32, blank=True, null=True)
    qr_code_image = models.ImageField(upload_to='qr_codes/', blank=True, null=True)
    is_qr_enabled = models.BooleanField(default=False)
    
    # Facebook Authentication
    facebook_id = models.CharField(max_length=100, blank=True, null=True)
    facebook_email = models.EmailField(blank=True, null=True)
    facebook_picture_url = models.URLField(blank=True, null=True)
    
    def generate_qr_secret(self):
        """Generate a new secret key for QR code authentication"""
        self.qr_secret_key = pyotp.random_base32()
        self.save()
        return self.qr_secret_key
    
    def generate_qr_code(self):
        """Generate QR code for Google Authenticator"""
        if not self.qr_secret_key:
            self.generate_qr_secret()
        
        totp = pyotp.TOTP(self.qr_secret_key)
        qr_uri = totp.provisioning_uri(
            name=self.username,
            issuer_name="Django Authentication App"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code image
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        self.qr_code_image.save(
            f'qr_code_{self.username}.png',
            ContentFile(buffer.getvalue()),
            save=True
        )
        
        return self.qr_code_image
    
    def verify_qr_code(self, token):
        """Verify QR code token"""
        if not self.qr_secret_key:
            return False
        
        totp = pyotp.TOTP(self.qr_secret_key)
        return totp.verify(token, valid_window=1)
    
    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.is_blocked = False
        self.blocked_until = None
        self.save()
    
    def increment_failed_attempts(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 3:
            from django.utils import timezone
            from datetime import timedelta
            self.is_blocked = True
            self.blocked_until = timezone.now() + timedelta(hours=1)  # Block for 1 hour
        self.save()


# Simple model for DRF demo (basic CRUD similar to GfG Book example)
class Note(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.title


# Exercise model for REST UI (fields similar to screenshot)
class Exercise(models.Model):
    name = models.CharField(max_length=120)
    category = models.CharField(max_length=80)
    sets = models.IntegerField(default=3)
    reps = models.CharField(max_length=20, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.name


# Lightweight activity models to drive dashboard metrics and history
class CryptoActivity(models.Model):
    OPERATION_CHOICES = (
        ("encrypt", "Encrypt"),
        ("decrypt", "Decrypt"),
    )

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="crypto_activities")
    cipher_type = models.CharField(max_length=40)
    operation = models.CharField(max_length=16, choices=OPERATION_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.user.username} {self.operation} {self.cipher_type}"


class AutomationAlert(models.Model):
    LEVEL_CHOICES = (
        ("info", "Info"),
        ("warning", "Warning"),
        ("error", "Error"),
    )

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="automation_alerts")
    level = models.CharField(max_length=16, choices=LEVEL_CHOICES, default="info")
    message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.level.upper()}: {self.message[:40]}"


class AnimeActivity(models.Model):
    ACTION_CHOICES = (
        ("trending", "Trending"),
        ("detail", "Detail"),
        ("search", "Search"),
    )

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="anime_activities")
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    media_id = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.user.username} {self.action} {self.media_id or ''}"