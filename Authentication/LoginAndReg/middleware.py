from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from .models import CustomUser

class AccountLockoutMiddleware(MiddlewareMixin):
    """
    Middleware to check if user account is locked and redirect accordingly
    """
    def process_request(self, request):
        if request.user.is_authenticated and hasattr(request.user, 'is_blocked'):
            user = request.user
            if user.is_blocked and user.blocked_until:
                if timezone.now() < user.blocked_until:
                    # User is still blocked
                    messages.error(
                        request, 
                        f'Your account is blocked until {user.blocked_until.strftime("%Y-%m-%d %H:%M")}. '
                        'Please try again later.'
                    )
                    return redirect('home')
                else:
                    # Block time has expired, unblock user
                    user.reset_failed_attempts()
        
        return None
