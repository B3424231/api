from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
import re
from .models import CustomUser
from .utils import validate_password_strength, validate_username, get_password_strength_score, get_password_strength_label

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2')
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        validate_username(username)
        return username
    
    def clean_password1(self):
        password1 = self.cleaned_data.get('password1')
        validate_password_strength(password1)
        return password1
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    qr_code = forms.CharField(max_length=6, required=False, help_text="Enter 6-digit code from Google Authenticator")

class QRCodeSetupForm(forms.Form):
    qr_code = forms.CharField(max_length=6, help_text="Enter 6-digit code from Google Authenticator to verify setup")

class TwoFactorForm(forms.Form):
    """Simple form for second-step authentication via QR/OTP code only."""
    qr_code = forms.CharField(max_length=6, required=True, help_text="Enter 6-digit code from Google Authenticator")