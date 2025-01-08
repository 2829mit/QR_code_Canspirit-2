from django.urls import path

from . import views


# URL patterns for the application
urlpatterns = [
    # Homepage
    path('', views.homepage, name='homepage'),

    # User authentication routes
    path('register/', views.register, name='register'),  # Registration page
    path('login/', views.user_login, name='login'),  # Login page
    path('logout/', views.user_logout, name='logout'),  # Logout route

    # Administrator dashboard routes
    path('administrator/dashboard/', views.admin_dashboard, name='admin_dashboard'),  # Admin dashboard
    path('administrator/dashboard/data/', views.admin_dashboard_data, name='admin_dashboard_data'),  # Admin dashboard data

    # User dashboard routes
    path('user/dashboard/', views.user_dashboard, name='user_dashboard'),  # User dashboard
    path('user/dashboard/data/', views.user_dashboard_data, name='user_dashboard_data'),  # User dashboard data

    # QR code generation and management routes for users
    path('user/', views.generate_qr_code, name='generate_qr_code'),  # Generate new QR code
    path('user/generic/', views.home, name='home'),
    path('user/vcard/', views.vcard, name='vcard'),
    path('user/mecard/', views.mecard, name='mecard'),
    path('user/email/', views.email, name='email'),
    path('user/geo/', views.geo, name='geo'),
    path('user/wifi/', views.wifi, name='wifi'),


    path('qrcode/<int:qr_id>/delete/', views.delete_qr_code, name='delete_qr_code'), # Delete a QR code
    path('qr/download/<int:qr_id>/', views.download_qr_code, name='download_qr_code'),  # Download a QR code

    # Administrator management routes for users
    path('administrator/manage_users/', views.admin_manage_users, name='admin_manage_users'),  # Manage users page
    path('administrator/manage_users/edit-quota/<int:user_id>/', views.edit_user_quota, name='edit_user_quota'),  # Edit user's QR code quota
    path('administrator/manage_users/delete/<int:user_id>/', views.delete_user, name='delete_user'),  # Delete a user
    path('administrator/manage_users/modify-permissions/<int:user_id>/', views.modify_permissions, name='modify_permissions'),  # Modify user permissions (e.g., admin privileges)

    # Admin view of all QR codes
    path('administrator/view-qrcodes/', views.admin_view_qrcodes, name='admin_view_qrcodes'),  # View all QR codes

    # User's view of their own QR codes
    path('user/view-qrcodes/', views.user_view_qrcodes, name='user_view_qrcodes'),  # View user's QR codes
    
    # Organization management routes
    path('administrator/organizations/', views.organization_list, name='organization_list'),  # List of organizations
    path('administrator/organizations/create/', views.organization_create, name='organization_create'),  # Create an organization
    path('administrator/organizations/edit/<int:pk>/', views.organization_edit, name='organization_edit'),  # Edit an organization
    path('administrator/organizations/delete/<int:pk>/', views.organization_delete, name='organization_delete'),  # Delete an organization
]
