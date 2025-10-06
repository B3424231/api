import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def validate_password_strength(password):
    """
    Validate password strength with comprehensive checks
    """
    errors = []
    
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long.')
    
    if not re.search(r'[A-Za-z]', password):
        errors.append('Password must contain at least one letter.')
    
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one number.')
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character.')
    
    # Check for common patterns
    if re.search(r'(.)\1{2,}', password):
        errors.append('Password cannot contain more than 2 consecutive identical characters.')
    

    if errors:
        raise ValidationError(errors)
    
    return True

def validate_username(username):
    """
    Validate username with comprehensive checks
    """
    errors = []
    
    if len(username) < 6:
        errors.append('Username must be at least 6 characters long.')
    
    if len(username) > 30:
        errors.append('Username must be no more than 30 characters long.')
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        errors.append('Username can only contain letters, numbers, and underscores.')
    
    if username.startswith('_') or username.endswith('_'):
        errors.append('Username cannot start or end with an underscore.')
    
    if re.search(r'_{2,}', username):
        errors.append('Username cannot contain consecutive underscores.')
    
    if errors:
        raise ValidationError(errors)
    
    return True

def get_password_strength_score(password):
    """
    Calculate password strength score (0-100)
    """
    score = 0
    
    # Length score (0-30 points)
    if len(password) >= 8:
        score += 10
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    
    # Character variety score (0-40 points)
    if re.search(r'[a-z]', password):
        score += 5
    if re.search(r'[A-Z]', password):
        score += 5
    if re.search(r'\d', password):
        score += 5
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 5
    if re.search(r'[^a-zA-Z0-9!@#$%^&*(),.?":{}|<>]', password):
        score += 10  # Bonus for other special characters
    
    # Pattern penalty (0-30 points deducted)
    if re.search(r'(.)\1{2,}', password):
        score -= 10  # Consecutive identical characters
    if re.search(r'(123|abc|qwe|asd|zxc)', password.lower()):
        score -= 10  # Common sequences
    if re.search(r'(password|admin|user|login)', password.lower()):
        score -= 20  # Common words
    
    return max(0, min(100, score))

def get_password_strength_label(score):
    """
    Get password strength label based on score
    """
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Fair"
    elif score < 90:
        return "Good"
    else:
        return "Strong"
