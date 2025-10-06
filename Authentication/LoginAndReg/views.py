from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import requests
from .models import CustomUser, Note, Exercise, CryptoActivity, AutomationAlert, AnimeActivity
from .forms import CustomUserCreationForm, LoginForm, QRCodeSetupForm, TwoFactorForm
import os
import smtplib
from email.message import EmailMessage
import threading
import time
from datetime import datetime
from rest_framework import viewsets, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import qrcode
import pyotp
from io import BytesIO
import base64


def home(request):
    # Home removed: send users to login page
    return redirect('login')

def anime(request):
    """Simple page shell for the Anime API UI; data fetched via existing endpoints."""
    return render(request, 'anime.html')

@login_required
def exercises_page(request):
    """Integrated Exercises UI that uses the DRF /api/exercises/ endpoints under the hood."""
    return render(request, 'exercises.html')

@login_required
def settings_view(request):
    """Settings hub page linking to profile, QR, Facebook and security."""
    return render(request, 'settings.html', {
        'user_obj': request.user
    })

@login_required
def profile_view(request):
    return render(request, 'profile.html', {
        'user_obj': request.user
    })

@login_required
def security_view(request):
    user = request.user
    context = {
        'mfa_active': user.is_qr_enabled,
        'failed_attempts': getattr(user, 'failed_login_attempts', 0),
        'blocked_until': getattr(user, 'blocked_until', None),
    }
    return render(request, 'security.html', context)

def anime_detail(request, anime_id: int):
    """Render a detail page for a specific anime. Data fetched client-side from API."""
    return render(request, 'anime_detail.html', { 'anime_id': anime_id })

def automation(request):
    """Simple shell page for Gmail Message Automation UI (front-end only for now)."""
    return render(request, 'automation.html')

@login_required
def automation_send(request):
    """Send an email via Gmail using environment variables for credentials.

    Required env vars:
      - GMAIL_USER
      - GMAIL_APP_PASSWORD (Gmail App Password)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        payload = request.POST

    to_address = (payload.get('to') or '').strip()
    subject = (payload.get('subject') or '').strip()
    body = payload.get('body') or ''
    when_str = (payload.get('when') or '').strip()
    include_digest = str(payload.get('include_anime_digest') or 'false').lower() in ('1','true','yes','on')

    if not to_address:
        return JsonResponse({'error': 'Recipient is required'}, status=400)

    gmail_user = os.environ.get('GMAIL_USER')
    gmail_pass = os.environ.get('GMAIL_APP_PASSWORD')
    if not gmail_user or not gmail_pass:
        return JsonResponse({'error': 'Server is not configured with Gmail credentials'}, status=500)

    def send_email(compose_only: bool=False):
        content = body
        if include_digest:
            # fetch top anime digest (top 5 trending)
            try:
                digest = anilist_fetch_trending_top_n(5)
                lines = ["\n\nTop Anime Today:"]
                for item in digest:
                    lines.append(f"- {item['title']} (Score: {item.get('score','N/A')}, Ep: {item.get('episodes','?')})")
                content += "\n" + "\n".join(lines)
            except Exception:
                pass

        msg = EmailMessage()
        msg['From'] = gmail_user
        msg['To'] = to_address
        msg['Subject'] = subject if subject else '(no subject)'
        msg.set_content(content)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(gmail_user, gmail_pass)
            smtp.send_message(msg)

    try:
        # If when is provided and in the future, schedule a background send
        if when_str:
            try:
                target = datetime.fromisoformat(when_str)
                delay = (target - datetime.now()).total_seconds()
            except Exception:
                delay = 0
            if delay > 5:
                def runner():
                    time.sleep(delay)
                    try:
                        send_email()
                        try:
                            AutomationAlert.objects.create(
                                user=request.user,
                                level='info',
                                message=f"Scheduled email sent to {to_address}: {subject or '(no subject)'}"
                            )
                        except Exception:
                            pass
                    except Exception:
                        pass
                threading.Thread(target=runner, daemon=True).start()
                # Log scheduling immediately
                try:
                    AutomationAlert.objects.create(
                        user=request.user,
                        level='info',
                        message=f"Email scheduled to {to_address} at {when_str}: {subject or '(no subject)'}"
                    )
                except Exception:
                    pass
                return JsonResponse({'ok': True, 'scheduled': True, 'message': 'Email scheduled'})

        # Immediate send
        send_email()
        try:
            AutomationAlert.objects.create(
                user=request.user,
                level='info',
                message=f"Email sent to {to_address}: {subject or '(no subject)'}"
            )
        except Exception:
            pass
        return JsonResponse({'ok': True, 'scheduled': False, 'message': 'Email sent'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def anilist_fetch_trending_top_n(n: int = 5):
    # Reuse existing GraphQL to get trending and simplify
    graphql_query = """
        query ($page: Int, $perPage: Int) {
            Page(page: $page, perPage: $perPage) {
                media(type: ANIME, sort: TRENDING_DESC) {
                    id
                    title { romaji english }
                    averageScore
                    episodes
                }
            }
        }
    """
    variables = {"page": 1, "perPage": max(1, int(n))}
    resp = requests.post(
        'https://graphql.anilist.co',
        json={'query': graphql_query, 'variables': variables},
        headers={'Content-Type': 'application/json'},
        timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"AniList error: HTTP {resp.status_code}")
    data = resp.json()
    items = []
    for m in data.get('data',{}).get('Page',{}).get('media',[]):
        title = m.get('title',{}).get('english') or m.get('title',{}).get('romaji')
        items.append({'id': m.get('id'), 'title': title, 'score': m.get('averageScore'), 'episodes': m.get('episodes')})
    return items

def anime_trending_rest(request):
    """Simple REST endpoint returning top trending anime (id, title, score, episodes).

    Note: kept as JSON without DRF viewsets for simplicity, but DRF is installed
    for future expansion, as per DRF patterns described here [GeeksforGeeks](https://www.geeksforgeeks.org/python/how-to-create-a-basic-api-using-django-rest-framework/).
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    try:
        limit = request.GET.get('limit', '10')
        try:
            limit_int = max(1, min(50, int(limit)))
        except Exception:
            limit_int = 10
        top = anilist_fetch_trending_top_n(limit_int)
        return JsonResponse({'results': top}, json_dumps_params={'ensure_ascii': False})
    except Exception as e:
        # Provide a friendly JSON error payload
        return JsonResponse({'error': 'Failed to fetch from AniList', 'details': str(e)}, status=502)

# =====================
# Automation Scheduler
# =====================
_AUTOMATION_STATE = {
    'running': False,
    'thread': None,
    'to_email': None,
    'logs': [],
    'interval': 600,  # seconds
    'start_at': None, # datetime or None
}

def _auto_log(message: str):
    ts = datetime.now().strftime('%H:%M:%S')
    entry = f"[{ts}] {message}"
    _AUTOMATION_STATE['logs'].append(entry)
    # keep last 200
    if len(_AUTOMATION_STATE['logs']) > 200:
        _AUTOMATION_STATE['logs'] = _AUTOMATION_STATE['logs'][-200:]

def _load_exercises_json():
    try:
        import json, os
        path = os.path.join(os.getcwd(), 'exercises.json')
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        # fallback sample
        return {
            'exercises': [
                {'name': 'Push-ups', 'category': 'strength', 'sets': 3, 'reps': '12', 'description': 'Standard push-ups.'},
                {'name': 'Plank', 'category': 'core', 'sets': 3, 'time': '45s', 'description': 'Hold a strong plank.'},
                {'name': 'Squats', 'category': 'legs', 'sets': 3, 'reps': '15', 'description': 'Bodyweight squats.'},
            ]
        }

def _random_exercise():
    import random
    data = _load_exercises_json()
    arr = data.get('exercises') or []
    if not arr:
        return None
    return random.choice(arr)

def _format_exercise_message(ex):
    now_str = datetime.now().strftime('%H:%M')
    msg = [f"EXERCISE ALERT ({now_str})", "", f"Exercise: {ex.get('name')}", f"Category: {str(ex.get('category','')).title()}", f"Sets: {ex.get('sets','?')}"]
    if 'reps' in ex:
        msg.append(f"Reps: {ex.get('reps')}")
    elif 'time' in ex:
        msg.append(f"Duration: {ex.get('time')}")
    msg.extend(["", f"Description: {ex.get('description','')}", "", "Time to get moving!"])
    return "\n".join(msg)

def _send_email(to_address: str, subject: str, body: str):
    gmail_user = os.environ.get('GMAIL_USER')
    gmail_pass = os.environ.get('GMAIL_APP_PASSWORD')
    if not gmail_user or not gmail_pass:
        raise RuntimeError('Server is not configured with Gmail credentials')

    msg = EmailMessage()
    msg['From'] = gmail_user
    msg['To'] = to_address
    msg['Subject'] = subject or '(no subject)'
    msg.set_content(body)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(gmail_user, gmail_pass)
        smtp.send_message(msg)

def _send_exercise_alert(to_address: str):
    ex = _random_exercise()
    if not ex:
        _auto_log('No exercise data available')
        return
    subject = f"Exercise Alert - {ex.get('name')}"
    body = _format_exercise_message(ex)
    _auto_log(f"Sending email to {to_address}...")
    _send_email(to_address, subject, body)
    _auto_log('Email sent successfully!')

def _scheduler_loop():
    _auto_log('Scheduler started')
    # wait until start_at if provided
    try:
        start_at = _AUTOMATION_STATE.get('start_at')
        if start_at and isinstance(start_at, datetime):
            delay = (start_at - datetime.now()).total_seconds()
            if delay > 0:
                for _ in range(int(delay)):
                    if not _AUTOMATION_STATE['running']:
                        _auto_log('Scheduler stopped before start time')
                        return
                    time.sleep(1)
    except Exception:
        pass
    # initial send at start
    try:
        if _AUTOMATION_STATE['to_email']:
            _send_exercise_alert(_AUTOMATION_STATE['to_email'])
    except Exception as e:
        _auto_log(f"Error on initial send: {e}")
    # loop by interval
    while _AUTOMATION_STATE['running']:
        interval = int(_AUTOMATION_STATE.get('interval', 600))
        if interval < 60:
            interval = 60
        for _ in range(interval):
            if not _AUTOMATION_STATE['running']:
                break
            time.sleep(1)
        if not _AUTOMATION_STATE['running']:
            break
        try:
            if _AUTOMATION_STATE['to_email']:
                _send_exercise_alert(_AUTOMATION_STATE['to_email'])
                _auto_log(f"Next alert scheduled in {interval//60} minutes...")
        except Exception as e:
            _auto_log(f"Error in scheduler: {e}")
            time.sleep(60)
    _auto_log('Scheduler stopped')

@login_required
def automation_status(request):
    return JsonResponse({
        'running': _AUTOMATION_STATE['running'],
        'to_email': _AUTOMATION_STATE['to_email'],
        'logs': _AUTOMATION_STATE['logs'][-50:],
    })

@login_required
def automation_start(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    payload = json.loads(request.body.decode('utf-8')) if request.body else request.POST
    to_email = (payload.get('to_email') or '').strip()
    interval_minutes = payload.get('interval_minutes')
    start_at_str = (payload.get('start_at') or '').strip()
    start_at_dt = None
    if start_at_str:
        try:
            start_at_dt = datetime.fromisoformat(start_at_str)
        except Exception:
            start_at_dt = None
    if not to_email:
        return JsonResponse({'error': 'to_email required'}, status=400)
    # update state
    _AUTOMATION_STATE['to_email'] = to_email
    if interval_minutes is not None:
        try:
            _AUTOMATION_STATE['interval'] = max(60, int(interval_minutes) * 60)
        except Exception:
            pass
    _AUTOMATION_STATE['start_at'] = start_at_dt
    if _AUTOMATION_STATE['running']:
        return JsonResponse({'ok': True, 'running': True})
    _AUTOMATION_STATE['running'] = True
    t = threading.Thread(target=_scheduler_loop, daemon=True)
    _AUTOMATION_STATE['thread'] = t
    t.start()
    return JsonResponse({'ok': True, 'running': True})

@login_required
def automation_stop(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    _AUTOMATION_STATE['running'] = False
    return JsonResponse({'ok': True, 'running': False})

@login_required
def automation_test_send(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    to_email = (json.loads(request.body.decode('utf-8')).get('to_email') if request.body else request.POST.get('to_email','')).strip()
    if not to_email:
        return JsonResponse({'error': 'to_email required'}, status=400)
    try:
        _send_exercise_alert(to_email)
        try:
            AutomationAlert.objects.create(
                user=request.user,
                level='info',
                message=f"Test alert email sent to {to_email}"
            )
        except Exception:
            pass
        return JsonResponse({'ok': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def automation_alerts(request):
    """Return recent automation alerts for the authenticated user."""
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    try:
        limit_str = request.GET.get('limit', '5')
        try:
            limit = max(1, min(50, int(limit_str)))
        except Exception:
            limit = 5
        qs = AutomationAlert.objects.filter(user=request.user).order_by('-created_at')[:limit]
        results = [
            {
                'level': a.level,
                'message': a.message,
                'created_at': a.created_at.isoformat()
            } for a in qs
        ]
        return JsonResponse({'results': results})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, 'Registration successful! Please log in.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})

def user_login(request):
    """Two-step login flow.
    Step 1: Username + password.
    Step 2: If user has 2FA enabled, ask only for QR/OTP code.
    """

    # Step 2: If session indicates pending 2FA, validate only QR code
    if request.method == 'POST' and request.session.get('pending_2fa_user_id'):
        form = TwoFactorForm(request.POST)
        if form.is_valid():
            qr_code = form.cleaned_data['qr_code']
            try:
                user = CustomUser.objects.get(id=request.session['pending_2fa_user_id'])
                # Lenient verification to tolerate small clock drift and formatting
                cleaned = ''.join(ch for ch in str(qr_code) if ch.isdigit())
                ok = False
                if user.qr_secret_key:
                    try:
                        ok = pyotp.TOTP(user.qr_secret_key).verify(cleaned, valid_window=2)
                    except Exception:
                        ok = False
                if ok:
                    user.reset_failed_attempts()
                    # Clear session flag and log in
                    request.session.pop('pending_2fa_user_id', None)
                    login(request, user)
                    messages.success(request, 'Login successful!')
                    return redirect('dashboard')
                else:
                    user.increment_failed_attempts()
                    messages.error(request, 'Invalid QR code.')
            except CustomUser.DoesNotExist:
                request.session.pop('pending_2fa_user_id', None)
                messages.error(request, 'Session expired. Please login again.')
        # Re-render QR-only form
        return render(request, 'login.html', {
            'two_factor': True,
            'form': form,
            'user_qr_image': getattr(CustomUser.objects.filter(id=request.session.get('pending_2fa_user_id')).first(), 'qr_code_image', None)
        })

    # Step 1: Handle normal credential submission
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            try:
                user = CustomUser.objects.get(username=username)
                
                # Check if user is blocked
                if user.is_blocked:
                    if user.blocked_until and timezone.now() < user.blocked_until:
                        messages.error(request, f'Account is blocked until {user.blocked_until.strftime("%Y-%m-%d %H:%M")}')
                        return render(request, 'login.html', {'form': form})
                    else:
                        user.reset_failed_attempts()
                
                user_auth = authenticate(request, username=username, password=password)
                
                if user_auth is not None:
                    if user.is_qr_enabled:
                        # Store pending state and render QR-only step
                        request.session['pending_2fa_user_id'] = user.id
                        return render(request, 'login.html', {
                            'two_factor': True,
                            'form': TwoFactorForm(),
                            'user_qr_image': user.qr_code_image
                        })
                    
                    user.reset_failed_attempts()
                    login(request, user_auth)
                    messages.success(request, 'Login successful!')
                    return redirect('dashboard')
                else:
                    user.increment_failed_attempts()
                    messages.error(request, f'Invalid credentials. Attempts remaining: {3 - user.failed_login_attempts}')
            except CustomUser.DoesNotExist:
                messages.error(request, 'User does not exist.')
    else:
        form = LoginForm()
    
    return render(request, 'login.html', {'form': form})

@login_required
def dashboard(request):
    """Dashboard with recent activity from all tools."""
    return render(request, 'dashboard.html', {'user': request.user})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_metrics(request):
    """Return counts for dashboard cards with actual data (no placeholders)."""
    user = request.user
    data = {
        'crypto_count': CryptoActivity.objects.filter(user=user).count(),
        'alerts_count': AutomationAlert.objects.filter(user=user).count(),
        'exercises_count': Exercise.objects.count(),
        'anime_count': AnimeActivity.objects.filter(user=user).count(),
    }
    return JsonResponse(data)

@login_required
def setup_qr_code(request):
    if request.method == 'POST':
        form = QRCodeSetupForm(request.POST)
        if form.is_valid():
            qr_code = form.cleaned_data['qr_code']
            # Lenient verification for setup confirmation
            cleaned = ''.join(ch for ch in str(qr_code) if ch.isdigit())
            ok = False
            if request.user.qr_secret_key:
                try:
                    ok = pyotp.TOTP(request.user.qr_secret_key).verify(cleaned, valid_window=2)
                except Exception:
                    ok = False
            if ok:
                request.user.is_qr_enabled = True
                request.user.save()
                messages.success(request, 'QR code authentication enabled successfully!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid QR code. Please try again.')
    else:
        form = QRCodeSetupForm()
        # Generate QR code if not already generated
        if not request.user.qr_secret_key:
            request.user.generate_qr_secret()
        if not request.user.qr_code_image:
            request.user.generate_qr_code()
    
    return render(request, 'setup_qr.html', {'form': form, 'qr_image': request.user.qr_code_image})

@login_required
def disable_qr_code(request):
    if request.method == 'POST':
        request.user.is_qr_enabled = False
        request.user.save()
        messages.success(request, 'QR code authentication disabled.')
    return redirect('dashboard')

@login_required
def disable_qr_confirm_password(request):
    """Alternate disable flow: confirm with account password."""
    if request.method != 'POST':
        return redirect('setup_qr')
    password = (request.POST.get('password') or '').strip()
    if not password:
        messages.error(request, 'Please enter your password to disable 2FA.')
        return redirect('setup_qr')
    try:
        if request.user.check_password(password):
            request.user.is_qr_enabled = False
            request.user.save()
            messages.success(request, '2FA disabled successfully using password confirmation.')
        else:
            messages.error(request, 'Incorrect password. 2FA was not disabled.')
    except Exception as e:
        messages.error(request, f'Failed to verify password: {str(e)}')
    return redirect('setup_qr')

def facebook_login(request):
    from django.conf import settings
    import urllib.parse
    
    # Facebook OAuth URL
    facebook_auth_url = (
        f"https://www.facebook.com/v18.0/dialog/oauth?"
        f"client_id={settings.FACEBOOK_APP_ID}&"
        f"redirect_uri={settings.FACEBOOK_REDIRECT_URI}&"
        f"scope=email,public_profile&"
        f"response_type=code"
    )
    
    return render(request, 'facebook_login.html', {
        'facebook_auth_url': facebook_auth_url
    })

def facebook_callback(request):
    from django.conf import settings
    import requests
    import json
    
    if request.method == 'GET':
        code = request.GET.get('code')
        if not code:
            messages.error(request, 'Facebook authentication failed: No authorization code received.')
            return redirect('login')
        
        try:
            # Exchange code for access token
            token_url = 'https://graph.facebook.com/v18.0/oauth/access_token'
            token_data = {
                'client_id': settings.FACEBOOK_APP_ID,
                'client_secret': settings.FACEBOOK_APP_SECRET,
                'redirect_uri': settings.FACEBOOK_REDIRECT_URI,
                'code': code
            }
            
            token_response = requests.post(token_url, data=token_data)
            token_json = token_response.json()
            
            if 'access_token' not in token_json:
                messages.error(request, 'Facebook authentication failed: No access token received.')
                return redirect('login')
            
            access_token = token_json['access_token']
            
            # Get user profile from Facebook
            profile_url = f'https://graph.facebook.com/v18.0/me?fields=id,name,email,picture&access_token={access_token}'
            profile_response = requests.get(profile_url)
            profile_data = profile_response.json()
            
            facebook_id = profile_data.get('id')
            email = profile_data.get('email')
            name = profile_data.get('name')
            picture_data = profile_data.get('picture', {})
            facebook_picture_url = picture_data.get('data', {}).get('url') if picture_data else None
            
            if not facebook_id:
                messages.error(request, 'Facebook authentication failed: No user ID received.')
                return redirect('login')
            
            # Check if user exists with this Facebook ID
            try:
                user = CustomUser.objects.get(facebook_id=facebook_id)
                # Update profile picture if available
                if facebook_picture_url:
                    user.facebook_picture_url = facebook_picture_url
                    user.save()
            except CustomUser.DoesNotExist:
                # Create new user or link to existing user
                if email:
                    try:
                        user = CustomUser.objects.get(email=email)
                        user.facebook_id = facebook_id
                        user.facebook_email = email
                        if facebook_picture_url:
                            user.facebook_picture_url = facebook_picture_url
                        user.save()
                    except CustomUser.DoesNotExist:
                        # Create new user
                        username = email.split('@')[0] + '_fb'
                        counter = 1
                        while CustomUser.objects.filter(username=username).exists():
                            username = f"{email.split('@')[0]}_fb_{counter}"
                            counter += 1
                        
                        user = CustomUser.objects.create_user(
                            username=username,
                            email=email,
                            first_name=name.split(' ')[0] if name else '',
                            last_name=' '.join(name.split(' ')[1:]) if name and len(name.split(' ')) > 1 else '',
                            facebook_id=facebook_id,
                            facebook_email=email,
                            facebook_picture_url=facebook_picture_url
                        )
                else:
                    # Create user without email
                    username = f"fb_user_{facebook_id}"
                    counter = 1
                    while CustomUser.objects.filter(username=username).exists():
                        username = f"fb_user_{facebook_id}_{counter}"
                        counter += 1
                    
                    user = CustomUser.objects.create_user(
                        username=username,
                        first_name=name.split(' ')[0] if name else '',
                        last_name=' '.join(name.split(' ')[1:]) if name and len(name.split(' ')) > 1 else '',
                        facebook_id=facebook_id,
                        facebook_picture_url=facebook_picture_url
                    )
            
            login(request, user)
            request.session['fb_logged_in'] = True
            messages.success(request, f'Welcome! You have been logged in via Facebook.')
            return redirect('dashboard')
            
        except Exception as e:
            messages.error(request, f'Facebook authentication failed: {str(e)}')
            return redirect('login')
    
    return redirect('login')

def logout_view(request):
    from django.contrib.auth import logout
    logout(request)
    request.session.pop('fb_logged_in', None)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

@login_required
def debug_qr(request):
    """Debug view to show QR code information"""
    user = request.user
    context = {
        'user': user,
        'qr_secret': user.qr_secret_key,
        'qr_image': user.qr_code_image,
        'qr_enabled': user.is_qr_enabled,
    }
    return render(request, 'debug_qr.html', context)

# AniList API Integration
def anilist_search_anime(request):
    """Search anime using AniList API"""
    if request.method == 'GET':
        query = request.GET.get('q', '')
        page = request.GET.get('page', 1)
        per_page = request.GET.get('per_page', 10)
        
        if not query:
            return JsonResponse({'error': 'Query parameter is required'}, status=400)
        
        # AniList GraphQL query
        graphql_query = """
        query ($search: String, $page: Int, $perPage: Int) {
            Page(page: $page, perPage: $perPage) {
                pageInfo {
                    total
                    currentPage
                    lastPage
                    hasNextPage
                    perPage
                }
                media(search: $search, type: ANIME, sort: POPULARITY_DESC) {
                    id
                    title {
                        romaji
                        english
                        native
                    }
                    description
                    coverImage {
                        large
                        medium
                    }
                    bannerImage
                    startDate {
                        year
                        month
                        day
                    }
                    endDate {
                        year
                        month
                        day
                    }
                    status
                    episodes
                    duration
                    genres
                    averageScore
                    popularity
                    studios {
                        nodes {
                            name
                        }
                    }
                    format
                    source
                    season
                    seasonYear
                }
            }
        }
        """
        
        variables = {
            "search": query,
            "page": int(page),
            "perPage": int(per_page)
        }
        
        try:
            response = requests.post(
                'https://graphql.anilist.co',
                json={'query': graphql_query, 'variables': variables},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                return JsonResponse(data)
            else:
                return JsonResponse({'error': 'Failed to fetch data from AniList'}, status=500)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def anilist_get_anime_details(request, anime_id):
    """Get detailed information about a specific anime"""
    if request.method == 'GET':
        graphql_query = """
        query ($id: Int) {
            Media(id: $id, type: ANIME) {
                id
                title {
                    romaji
                    english
                    native
                }
                description
                coverImage {
                    large
                    extraLarge
                }
                bannerImage
                startDate {
                    year
                    month
                    day
                }
                endDate {
                    year
                    month
                    day
                }
                status
                episodes
                duration
                genres
                averageScore
                popularity
                studios {
                    nodes {
                        name
                    }
                }
                format
                source
                season
                seasonYear
                characters {
                    nodes {
                        id
                        name {
                            full
                        }
                        image {
                            large
                        }
                    }
                }
                staff {
                    nodes {
                        id
                        name {
                            full
                        }
                        image {
                            large
                        }
                    }
                }
                relations {
                    edges {
                        relationType
                        node {
                            id
                            title {
                                romaji
                            }
                            type
                        }
                    }
                }
                recommendations {
                    nodes {
                        mediaRecommendation {
                            id
                            title {
                                romaji
                            }
                            coverImage {
                                medium
                            }
                        }
                    }
                }
            }
        }
        """
        
        variables = {"id": int(anime_id)}
        
        try:
            response = requests.post(
                'https://graphql.anilist.co',
                json={'query': graphql_query, 'variables': variables},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                return JsonResponse(data)
            else:
                return JsonResponse({'error': 'Failed to fetch anime details'}, status=500)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def anilist_get_trending(request):
    """Get trending anime from AniList"""
    if request.method == 'GET':
        page = request.GET.get('page', 1)
        per_page = request.GET.get('per_page', 10)
        
        graphql_query = """
        query ($page: Int, $perPage: Int) {
            Page(page: $page, perPage: $perPage) {
                pageInfo {
                    total
                    currentPage
                    lastPage
                    hasNextPage
                    perPage
                }
                media(type: ANIME, sort: TRENDING_DESC, status: RELEASING) {
                    id
                    title {
                        romaji
                        english
                        native
                    }
                    description
                    coverImage {
                        large
                        medium
                    }
                    bannerImage
                    startDate {
                        year
                        month
                        day
                    }
                    status
                    episodes
                    duration
                    genres
                    averageScore
                    popularity
                    studios {
                        nodes {
                            name
                        }
                    }
                    format
                    season
                    seasonYear
                }
            }
        }
        """
        
        variables = {
            "page": int(page),
            "perPage": int(per_page)
        }
        
        try:
            response = requests.post(
                'https://graphql.anilist.co',
                json={'query': graphql_query, 'variables': variables},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                return JsonResponse(data)
            else:
                return JsonResponse({'error': 'Failed to fetch trending anime'}, status=500)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# DRF ViewSet for Note model
class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['id', 'title', 'content', 'created_at']

class NoteViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all().order_by('-created_at')
    serializer_class = NoteSerializer

# DRF for Exercise
class ExerciseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exercise
        fields = ['id', 'name', 'category', 'sets', 'reps', 'description', 'created_at']

class ExerciseViewSet(viewsets.ModelViewSet):
    queryset = Exercise.objects.all().order_by('-created_at')
    serializer_class = ExerciseSerializer

def jokes(request):
    """Jokes page with API integration and QR code generation."""
    return render(request, 'jokes.html')

def get_joke_api(request):
    """Fetch a joke from a public API."""
    try:
        # Using JokesAPI (free, no auth required)
        response = requests.get('https://v2.jokeapi.dev/joke/Any?blacklistFlags=nsfw,religious,political,racist,sexist,explicit&type=single')
        
        if response.status_code == 200:
            data = response.json()
            joke_text = data.get('joke', 'No joke found')
        else:
            # Fallback to another API
            response = requests.get('https://official-joke-api.appspot.com/random_joke')
            if response.status_code == 200:
                data = response.json()
                joke_text = f"{data.get('setup', '')} {data.get('punchline', '')}"
            else:
                joke_text = "Why don't scientists trust atoms? Because they make up everything!"
        
        # Generate QR code for the joke
        qr_code_data = generate_qr_code(joke_text)
        
        return JsonResponse({
            'success': True,
            'joke': joke_text,
            'qr_code': qr_code_data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e),
            'joke': "Why don't scientists trust atoms? Because they make up everything!",
            'qr_code': generate_qr_code("Why don't scientists trust atoms? Because they make up everything!")
        })

def generate_qr_code(text):
    """Generate QR code for given text and return as base64 image."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        return None

@login_required
def debug_otp(request):
    """Debug helper: show server time and current OTP for the logged-in user.
    Only available when DEBUG is True and for staff users.
    """
    from django.conf import settings
    if not (getattr(settings, 'DEBUG', False) and request.user.is_staff):
        return JsonResponse({'error': 'Not allowed'}, status=403)
    if not request.user.qr_secret_key:
        return JsonResponse({'error': 'No QR secret set for user'}, status=400)
    try:
        now_code = pyotp.TOTP(request.user.qr_secret_key).now()
        return JsonResponse({
            'server_time': datetime.now().isoformat(),
            'current_totp': now_code
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def cryptography(request):
    """Cryptography page with Atbash, Caesar, and Vigenere ciphers."""
    return render(request, 'cryptography.html')

def encrypt_decrypt_api(request):
    """Handle encryption and decryption requests with QR code generation."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body.decode('utf-8'))
        text = data.get('text', '').strip()
        cipher_type = data.get('cipher_type', '').lower()
        operation = data.get('operation', '').lower()  # 'encrypt' or 'decrypt'
        key = data.get('key', '')
        
        if not text:
            return JsonResponse({'error': 'Text is required'}, status=400)
        
        result_text = ''
        
        if cipher_type == 'atbash':
            result_text = atbash_cipher(text)
        elif cipher_type == 'caesar':
            try:
                shift = int(key) if key else 3
                result_text = caesar_cipher(text, shift, operation == 'decrypt')
            except ValueError:
                return JsonResponse({'error': 'Caesar cipher requires a numeric key'}, status=400)
        elif cipher_type == 'vigenere':
            if not key:
                return JsonResponse({'error': 'Vigenere cipher requires a key'}, status=400)
            result_text = vigenere_cipher(text, key, operation == 'decrypt')
        else:
            return JsonResponse({'error': 'Invalid cipher type'}, status=400)
        
        # Generate QR codes for both original and result text
        original_qr = generate_qr_code(f"Original: {text}")
        result_qr = generate_qr_code(f"Result: {result_text}")
        combined_qr = generate_qr_code(f"Original: {text}\nResult: {result_text}")
        
        return JsonResponse({
            'success': True,
            'original_text': text,
            'result_text': result_text,
            'cipher_type': cipher_type,
            'operation': operation,
            'key': key,
            'qr_codes': {
                'original': original_qr,
                'result': result_qr,
                'combined': combined_qr
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

def atbash_cipher(text):
    """Atbash cipher - reverses the alphabet (A=Z, B=Y, etc.)."""
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                # A=0, Z=25, so A maps to Z (25), B maps to Y (24), etc.
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            else:
                # a=0, z=25, so a maps to z (25), b maps to y (24), etc.
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return ''.join(result)

def caesar_cipher(text, shift, decrypt=False):
    """Caesar cipher with customizable shift value."""
    if decrypt:
        shift = -shift
    
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def vigenere_cipher(text, key, decrypt=False):
    """Vigenere cipher with repeating key."""
    result = []
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            
            if decrypt:
                shift = -shift
            
            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)