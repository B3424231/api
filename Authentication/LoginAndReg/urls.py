from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
# DRF router for Note
from .views import NoteViewSet, ExerciseViewSet
router.register(r'notes', NoteViewSet, basename='note')
router.register(r'exercises', ExerciseViewSet, basename='exercise')

urlpatterns = [
    path('', views.home, name='home'),
    path('anime/', views.anime, name='anime'),
    path('exercises/', views.exercises_page, name='exercises_page'),
    path('settings/', views.settings_view, name='settings'),
    path('settings/profile/', views.profile_view, name='profile'),
    path('settings/security/', views.security_view, name='security'),
    path('anime/<int:anime_id>/', views.anime_detail, name='anime_detail'),
    path('automation/', views.automation, name='automation'),
    path('automation/send/', views.automation_send, name='automation_send'),
    path('automation/status/', views.automation_status, name='automation_status'),
    path('automation/alerts/', views.automation_alerts, name='automation_alerts'),
    path('automation/start/', views.automation_start, name='automation_start'),
    path('automation/stop/', views.automation_stop, name='automation_stop'),
    path('automation/test-send/', views.automation_test_send, name='automation_test_send'),
    # DRF router
    path('api/', include(router.urls)),
    path('api/anime/trending/', views.anime_trending_rest, name='api_anime_trending'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('api/metrics/dashboard/', views.dashboard_metrics, name='api_dashboard_metrics'),
    path('setup-qr/', views.setup_qr_code, name='setup_qr'),
    path('disable-qr/', views.disable_qr_code, name='disable_qr'),
    path('disable-qr/password/', views.disable_qr_confirm_password, name='disable_qr_password'),
    path('facebook-login/', views.facebook_login, name='facebook_login'),
    path('facebook-callback/', views.facebook_callback, name='facebook_callback'),
    path('debug-qr/', views.debug_qr, name='debug_qr'),
    # Jokes functionality
    path('jokes/', views.jokes, name='jokes'),
    path('get-joke/', views.get_joke_api, name='get_joke_api'),
    # Cryptography functionality
    path('cryptography/', views.cryptography, name='cryptography'),
    path('crypto-process/', views.encrypt_decrypt_api, name='crypto_process'),
    path('debug/otp/', views.debug_otp, name='debug_otp'),
    # AniList API endpoints
    path('api/anilist/search/', views.anilist_search_anime, name='anilist_search'),
    path('api/anilist/anime/<int:anime_id>/', views.anilist_get_anime_details, name='anilist_anime_details'),
    path('api/anilist/trending/', views.anilist_get_trending, name='anilist_trending'),
]
