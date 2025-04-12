from django.urls import path

from . import views


# URL patterns for the application
urlpatterns = [
    # Homepage and authentication
    path('', views.homepage, name='homepage'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    # QR Code Generation Routes (Specific first)
    path('user/pdf/', views.pdf_qr, name='pdf'),
    path('user/url/', views.url_qr, name='url'),
    path('user/social_media/', views.social_media_qr, name='social_media'),
    path('user/logo/', views.logo_qr, name='logo'),
    path('user/email/', views.email_qr, name='email'),
    path('user/vcard/', views.vcard, name='vcard'),
    path('user/mecard/', views.mecard, name='mecard'),
    path('user/geo/', views.geo, name='geo'),
    path('user/wifi/', views.wifi, name='wifi'),
    path('user/generic/', views.generic, name='generic'),

    # User dashboard and QR management
    path('user/home/', views.home, name='home'),
    path('user/dashboard/', views.user_dashboard, name='user_dashboard'),
    path('user/view-qrcodes/', views.user_view_qrcodes, name='user_view_qrcodes'),
    path('qrcode/<int:qr_id>/delete/', views.delete_qr_code, name='delete_qr_code'),
    path('qr/download/<int:qr_id>/', views.download_qr_code, name='download_qr_code'),
    path('check-qr-status/<int:qr_id>/', views.check_qr_status, name='check_qr_status'),
    path('get-recent-qrcodes/', views.get_recent_qrcodes, name='get_recent_qrcodes'),
    path('user/analytics-dashboard/', views.analytics_dashboard, name='analytics_dashboard'),

    # Administrator routes
    path('administrator/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('administrator/dashboard/data/', views.admin_dashboard_data, name='admin_dashboard_data'),
    path('administrator/manage_users/', views.admin_manage_users, name='admin_manage_users'),
    path('administrator/manage_users/edit-quota/<int:user_id>/', views.edit_user_quota, name='edit_user_quota'),
    path('administrator/manage_users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('administrator/manage_users/modify-permissions/<int:user_id>/', views.modify_permissions, name='modify_permissions'),
    path('administrator/view-qrcodes/', views.admin_view_qrcodes, name='admin_view_qrcodes'),

    # Organization management
    path('administrator/organizations/', views.organization_list, name='organization_list'),
    path('administrator/organizations/create/', views.organization_create, name='organization_create'),
    path('administrator/organizations/edit/<int:pk>/', views.organization_edit, name='organization_edit'),
    path('administrator/organizations/delete/<int:pk>/', views.organization_delete, name='organization_delete'),

    # QR Redirect Route
    path('qr/<int:qr_id>/', views.qr_redirect, name='qr_redirect'),
]