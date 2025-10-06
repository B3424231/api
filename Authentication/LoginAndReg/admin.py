from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_qr_enabled', 'is_blocked', 'failed_login_attempts')
    list_filter = ('is_qr_enabled', 'is_blocked', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    
    fieldsets = UserAdmin.fieldsets + (
        ('Authentication Settings', {
            'fields': ('failed_login_attempts', 'is_blocked', 'blocked_until')
        }),
        ('QR Code Authentication', {
            'fields': ('qr_secret_key', 'qr_code_image', 'is_qr_enabled')
        }),
        ('Facebook Authentication', {
            'fields': ('facebook_id', 'facebook_email')
        }),
    )
    
    readonly_fields = ('qr_secret_key', 'qr_code_image')