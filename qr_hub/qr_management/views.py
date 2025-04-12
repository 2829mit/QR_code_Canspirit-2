import sys
from django.contrib import messages
from io import BytesIO
import os
from pyexpat.errors import messages
from django import forms
from django.urls import reverse
import qrcode
import re
from django.db import transaction
from django.utils import timezone
import segno
import base64
import io
from django.views.decorators.http import require_POST
from PIL import Image
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db.models import Count, F
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, HttpResponseForbidden, FileResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpRequest
import segno.helpers
from .forms import GenericQRCodeForm, UserRegistrationForm,OrganizationForm,WiFiQRCodeForm, GeoQRCodeForm, VCardQRCodeForm, MeCardQRCodeForm, EmailQRCodeForm, PDFQRCodeForm, URLQRCodeForm, SocialMediaQRCodeForm, LogoQRCodeForm, QRCodeGenerationForm
from .models import (
    QRCode, Organization, QRGeneric, QRVCard, QRMeCard,
    QREmail, QRGeo, QRWiFi, QRPDF, QRUrl, QRSocialMedia, QRLogo
)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging
import json
import requests
from urllib.parse import quote
import cloudinary.uploader
import time
import cloudinary
import uuid
import requests
from django.shortcuts import redirect, get_object_or_404
from django.utils import timezone
from qr_management.models import QRCode 
try:
    from django.contrib.gis.geoip2 import GeoIP2
    geo_available = True
except ImportError:
    geo_available = False

try:
    import user_agents
    ua_available = True
except ImportError:
    ua_available = False

logger = logging.getLogger(__name__)


User = get_user_model()

def homepage(request):
    """
    Renders the homepage of the QR Hub application.

    This view returns the homepage template, which is typically 
    the landing page of the web application.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered HTML template for the homepage.
    """
    return render(request, 'qr_management/homepage.html', {})

def register(request):
    """
    Handles user registration by displaying the registration form and processing 
    the form submission.

    If the request method is POST, the form data is validated, a new user is created, 
    and the user is logged in automatically. If the request method is GET, an empty 
    form is displayed.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered registration template, or a redirect to the homepage
                      after successful registration.
    """
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            # Save the user, but don't commit to the database yet
            user = form.save(commit=False)
            organization_id = request.POST.get('organization')
            if organization_id != "none":
                user.organization = Organization.objects.get(id=organization_id)
            # Set the password (hashed) before saving the user
            user.set_password(form.cleaned_data['password'])
            user.save()  # Save the user to the database
            
            # Log the user in immediately after registration
            login(request, user)
            
            # Redirect to the homepage after successful registration
            return redirect('user_dashboard')
    else:
        # If it's a GET request, display an empty registration form
        form = UserRegistrationForm()

    organizations = Organization.objects.all()
    # Render the registration page with the form
    return render(request, 'qr_management/register.html', {'form': form, 'organizations': organizations})


def user_login(request):
    """
    Handles user login by authenticating the user and redirecting them 
    based on their role (admin or regular user).

    If the request method is POST, the username and password are extracted 
    from the form data and the user is authenticated. If authentication is 
    successful, the user is logged in and redirected to the appropriate dashboard.
    If authentication fails, an error message is displayed.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered login page, or a redirect to the appropriate dashboard.
    """
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Authenticate the user with the provided username and password
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Log the user in if authentication is successful
            login(request, user)
            
            # Redirect the user to the appropriate dashboard based on their role
            if user.is_staff:  # Admin user
                return redirect('admin_dashboard')
            else:  # Regular user
                return redirect('user_dashboard')
        else:
            # Render the login page with an error message if authentication fails
            return render(request, 'qr_management/login.html', {'error': 'Invalid credentials'})
    
    # Render the login page for GET requests (or if form submission fails)
    return render(request, 'qr_management/login.html')

@login_required  # Ensure that the user is logged in before accessing this view
def user_logout(request):
    """
    Logs the user out and redirects them to the homepage.

    This view uses the `logout` function to log the user out of the session.
    After logging out, the user is redirected to the homepage.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A redirect to the homepage after the user is logged out.
    """
    # Log the user out
    logout(request)
    
    # Redirect the user to the homepage after logging out
    return redirect('homepage')

@login_required  # Ensure the user is logged in before accessing this view
def admin_dashboard(request):
    """
    Renders the administrator dashboard with key statistics and top users.

    This view gathers and displays statistics about the total number of users, 
    total QR codes created, top 3 users by QR codes created, and top 3 users 
    who have exhausted their QR code quota. Only users with admin privileges 
    can access this dashboard.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered admin dashboard template with the statistics.
    """
    # Redirect non-admin users to the login page
    if not request.user.is_staff:
        return redirect('login')

    # Gather statistics for the admin dashboard
    total_users = User.objects.count()  # Total number of users in the system
    total_qr_codes = QRCode.objects.count()  # Total number of QR codes created


    # Prepare the context to be passed to the template
    context = {
        'total_users': total_users,
        'total_qr_codes': total_qr_codes,
    }

    # Render the dashboard template with the gathered data
    return render(request, 'qr_management/admin_dashboard.html', context)


@login_required  # Ensure the user is logged in before accessing this view
def user_dashboard(request):
    """
    Renders the user dashboard with a welcome message, QR code creation statistics, 
    and the user's QR codes.

    This view retrieves the user's information and displays the number of QR codes created,
    the remaining quota, and a list of the QR codes the user has generated. Only authenticated 
    users can access this dashboard.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: The rendered user dashboard template with the user's data.
    """
    try:
        print("Fetching user dashboard data...")  # Debugging
        user = request.user
        qr_codes = QRCode.objects.filter(user=user).order_by('-created_at')[:3]
        
        # Force QR generation for any codes without URLs
        for qr in qr_codes:
            if not qr.cloudinary_url:
                print(f"Regenerating QR code {qr.id}...")  # Debugging
                redirect_url = request.build_absolute_uri(reverse('qr_redirect', kwargs={'qr_id': qr.id})).replace('127.0.0.1', '192.168.29.181')  # Replace with your actual IPv4 address
                qr.generate_and_upload_qr(redirect_url)
                qr.refresh_from_db()

        organization_qr_codes = []

        if user.organization:
            organization_qr_codes = QRCode.objects.filter(organization=user.organization)

        context = {
            'welcome_message': f"Welcome, {user.username}!",  # Display a personalized welcome message
            'user': user,
            'qr_codes': qr_codes,
            'qr_codes_created': user.qr_codes_created,
            'remaining_quota': max(user.qr_quota - user.qr_codes_created, 0),
            'organization_qr_codes': organization_qr_codes,
            'organization': user.organization,
        }
        
        return render(request, 'qr_management/user_dashboard.html', context)
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")  # Debugging
        return render(request, 'qr_management/user_dashboard.html', {'error': str(e)})


@login_required
def user_view_qrcodes(request):
    try:
        qrcodes = QRCode.objects.filter(user=request.user).order_by('-created_at')
        # Generate QR codes for display if needed
        for qr in qrcodes:
            if not hasattr(qr, 'qr_image') or not qr.qr_image:
                # Regenerate QR code
                qr_gen = segno.make(qr.content)
                buffer = io.BytesIO()
                qr_gen.save(buffer, kind='png', scale=5)
                buffer.seek(0)
                qr.qr_image = base64.b64encode(buffer.getvalue()).decode()
                qr.save()

        return render(request, 'qr_management/user_view_qrcodes.html', {
            'qrcodes': qrcodes
        })
    except Exception as e:
        print(f"QR History Error: {e}")  # For debugging
        return render(request, 'qr_management/user_view_qrcodes.html', {
            'error': f"Error loading QR codes: {str(e)}"
        })


@login_required  # Ensure the user is logged in before accessing this view
def admin_dashboard_data(request):
    """
    Fetches and renders a list of all QR codes for the admin dashboard.

    This view is designed to handle the request for displaying a list of QR codes 
    in the admin dashboard, either as a full page or through AJAX requests 
    (depending on the implementation).

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A rendered partial template containing the list of all QR codes.
    """
    # Fetch all QR codes in the system
    all_qr_codes = QRCode.objects.select_related('user', 'organization').all()

    context = {
        'all_qr_codes': all_qr_codes,
    }

    # Render and return the partial template for the admin QR code list
    return render(request, 'qr_management/partials/admin_qr_list.html', context)



@login_required
def user_dashboard_data(request):
    try:
        user = request.user
        recent_qrcodes = QRCode.objects.filter(user=user).order_by('-created_at')[:5]
        
        qrcodes_data = []
        for qr in recent_qrcodes:
            qr_data = {
                'id': qr.id,
                'type': qr.qr_type,
                'created_at': qr.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'content': qr.content if hasattr(qr, 'content') else None,
            }
            qrcodes_data.append(qr_data)
        max_qr=user.qr_quota
        remaining_qr=max(user.qr_quota - user.qr_codes_created, 0)

        context = {
        'user': user,
        'recent_qrcodes': recent_qrcodes,
        'qr_codes_created': user.qr_codes_created,
        'remaining_quota': remaining_qr,
        'max_qr': max_qr,
    }
        print("QR Quota:", max_qr)
        print("Remaining QR:", remaining_qr)
        return render(request, 'qr_management/user_dashboard.html', context)
            
       
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'response_message': str(e)
        }, status=500)

# Function to sanitize filenames
def sanitize_filename(content):
    """
    This function sanitizes the content by removing any characters 
    that are not allowed in filenames (e.g., ':' on Windows).
    """
    return re.sub(r'[<>:"/\\|?*]', '_', content)

@login_required  # Ensure that the user is logged in before accessing this view
def generate_qr_code(request, qr_code_id):
    try:
        qr_code = QRCode.objects.get(id=qr_code_id, user=request.user)
        
        redirection_url = request.build_absolute_uri(
            reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
        )
        # Print the URL to the terminal
        print(f"Generating QR code with redirection URL: {redirection_url}")
        sys.stdout.flush()  # Force immediate output

        cloudinary_url = qr_code.generate_and_upload_qr(redirection_url)
        if not cloudinary_url:
            raise Exception("Failed to upload QR code to Cloudinary")

        # Print the Cloudinary URL to the terminal
        print(f"QR Code successfully uploaded. Cloudinary URL: {cloudinary_url}")
        sys.stdout.flush()  # Force immediate output

        return JsonResponse({'cloudinary_url': cloudinary_url})
    except Exception as e:
        print(f"QR Code Generation Error for QRCode id {qr_code_id}: {e}")
        sys.stdout.flush()
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def delete_qr_code(request, qr_id):
    qr_code = get_object_or_404(QRCode, id=qr_id)
    user = qr_code.user

    if user != request.user and not request.user.is_staff:
        raise PermissionDenied("You do not have permission to delete this QR code.")

    qr_code.delete()

    if user:
        user.qr_codes_created = user.qrcodes.count()
        user.save()

    if request.user.is_staff:
        return redirect('admin_view_qrcodes')
    else:
        return redirect('user_view_qrcodes')

@login_required  # Ensure that the user is logged in before accessing this view
def admin_view_qrcodes(request):
    """
    Displays a list of all QR codes in the system for admins. This view also handles 
    AJAX requests by rendering a partial template with the QR code list.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A rendered page displaying the QR codes list or a partial 
        template for AJAX requests.
    """
    # Ensure the user is an admin
    if not request.user.is_staff:
        return redirect('login')  # Redirect non-admin users to the login page

    # Retrieve all QR codes along with their associated user details
    all_qr_codes = QRCode.objects.select_related('user', 'organization').all()

    context = {
        'all_qr_codes': all_qr_codes,
    }

    # Handle AJAX requests by rendering a partial template
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return render(request, 'qr_management/partials/admin_qr_list.html', context)

    # Render the full QR code list page for non-AJAX requests
    return render(request, 'qr_management/admin_view_qrcodes.html', context)


@login_required  # Ensure that the user is logged in before accessing this view
def download_qr_code(request, qr_id):
    """
    Allows a user to download a QR code image they created. Admin users can also download any QR code.
    The image is served as an attachment, prompting the user to download the file.
    """
    qr_code = get_object_or_404(QRCode, id=qr_id)

    # Ensure that only the owner or an admin can download the QR code
    if qr_code.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("You do not have permission to download this QR code.")

    # Get QR data and handle missing related objects
    qr_data = get_qr_data(qr_code)
    if not qr_data:
        return JsonResponse({"error": "QR code data is missing or invalid."}, status=400)

    # Generate the QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Prepare the image for response
    img_io = io.BytesIO()
    img.save(img_io, format="PNG")
    img_io.seek(0)

    # Set up FileResponse
    filename = f"qr_code_{qr_code.id}.png"
    response = FileResponse(img_io, as_attachment=True, filename=filename)
    response["Content-Type"] = "image/png"
    return response

def get_qr_data(qr_code):
    """
    Retrieves the data associated with a QR code, handling missing related objects gracefully.
    """
    try:
        if hasattr(qr_code, 'wifi_details') and qr_code.wifi_details:
            return f"WIFI:T:{qr_code.wifi_details.security};S:{qr_code.wifi_details.ssid};P:{qr_code.wifi_details.password};;"
        elif hasattr(qr_code, 'geo_details') and qr_code.geo_details:
            return f"geo:{qr_code.geo_details.latitude},{qr_code.geo_details.longitude}"
        elif hasattr(qr_code, 'email_details') and qr_code.email_details:
            return f"mailto:{qr_code.email_details.recipient}?subject={qr_code.email_details.subject}&body={qr_code.email_details.body}"
        elif hasattr(qr_code, 'mecard_details') and qr_code.mecard_details:
            return f"MECARD:N:{qr_code.mecard_details.name};TEL:{qr_code.mecard_details.phone};EMAIL:{qr_code.mecard_details.email};ADR:{qr_code.mecard_details.address};"
        elif hasattr(qr_code, 'vcard_details') and qr_code.vcard_details:
            return f"BEGIN:VCARD\nVERSION:3.0\nN:{qr_code.vcard_details.name}\nFN:{qr_code.vcard_details.displayname}\nTEL:{qr_code.vcard_details.phone}\nEMAIL:{qr_code.vcard_details.email}\nADR:{qr_code.vcard_details.address}\nORG:{qr_code.vcard_details.organization}\nEND:VCARD"
        elif hasattr(qr_code, 'url_details') and qr_code.url_details:
            return qr_code.url_details.url  # Ensure URL is returned for URL QR codes
        elif hasattr(qr_code, 'pdf_details') and qr_code.pdf_details:
            return qr_code.pdf_details.pdf_file.url
        elif hasattr(qr_code, 'social_media_details') and qr_code.social_media_details:
            return qr_code.social_media_details.url
        elif hasattr(qr_code, 'logo_details') and qr_code.logo_details:
            return qr_code.logo_details.content
        else:
            return "No data available for this QR code."
    except Exception as e:
        logger.error(f"Error retrieving QR code data: {str(e)}")
        return f"Error retrieving QR code data: {str(e)}"

@login_required  # Ensure that the user is logged in before accessing this view
def admin_manage_users(request):
    """
    Displays a list of all users for admin management. Only accessible by admin users.
    If the current user is not an admin, they are redirected to the login page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A rendered page displaying a list of all users.
    """
    # Ensure the user is an admin before granting access to this view
    if not request.user.is_staff:
        return redirect('login')

    # Fetch all users from the database
    users = User.objects.all()

    # Render the admin user management page with the list of users
    return render(request, 'qr_management/admin_manage_users.html', {'users': users})

@login_required  # Ensure that the user is logged in before accessing this view
def edit_user_quota(request, user_id):
    """
    Allows an admin to edit a user's QR code generation quota. 
    Only accessible by admin users.

    Args:
        request (HttpRequest): The HTTP request object.
        user_id (int): The ID of the user whose quota is being edited.

    Returns:
        HttpResponse: A rendered page for quota editing or a redirect after saving changes.
    """
    # Ensure the user is an admin before granting access to this view
    if not request.user.is_staff:
        return redirect('login')

    # Fetch the user by ID, return a 404 if not found
    user = get_object_or_404(User, id=user_id)

    # If the request method is POST, process the form submission
    if request.method == 'POST':
        # Get the new quota value from the form
        new_quota = request.POST.get('quota')

        # Update the user's profile with the new quota value
        user.qr_quota = int(new_quota)  # Convert to integer
        user.save()  # Save the changes to the profile

        # Redirect to the user management page after saving
        return redirect('admin_manage_users')

    # If it's a GET request, render the form for quota editing
    return render(request, 'qr_management/edit_quota.html', {'user': user})

@login_required  # Ensure that the user is logged in before accessing this view
def delete_user(request, user_id):
    """
    Allows an admin to delete a user account. 
    Prevents admins from deleting themselves.

    Args:
        request (HttpRequest): The HTTP request object.
        user_id (int): The ID of the user to be deleted.

    Returns:
        HttpResponse: A redirect to the user management page after deletion.
    """
    # Ensure the user is an admin before granting access to this view
    if not request.user.is_staff:
        return redirect('login')

    # Fetch the user by ID, return a 404 if not found
    user_to_delete = get_object_or_404(User, id=user_id)

    # Prevent the admin from deleting their own account
    if user_to_delete == request.user:
        return HttpResponseForbidden("You cannot delete your own account.")

    # Delete the user and their associated profile
    user_to_delete.delete()

    # Redirect to the user management page after deletion
    return redirect('admin_manage_users')

@login_required  # Ensure that the user is logged in before accessing this view
def modify_permissions(request, user_id):
    """
    Allows an admin to modify a user's permissions, such as granting or revoking admin privileges.

    Args:
        request (HttpRequest): The HTTP request object.
        user_id (int): The ID of the user whose permissions are to be modified.

    Returns:
        HttpResponse: A redirect to the user management page after permission modification.
    """
    # Ensure the user is an admin before granting access to this view
    if not request.user.is_staff:
        return redirect('login')

    # Fetch the user by ID, return a 404 if not found
    user_to_modify = get_object_or_404(User, id=user_id)

    # Handle POST request to modify user permissions
    if request.method == 'POST':
        # Check if the 'is_staff' checkbox is checked to grant admin privileges
        is_staff = request.POST.get('is_staff') == 'on'
        user_to_modify.is_staff = is_staff
        user_to_modify.save()

        # Redirect to the user management page after updating permissions
        return redirect('admin_manage_users')

    # Render the permission modification form for the selected user
    return render(request, 'qr_management/modify_permissions.html', {'user': user_to_modify})


@login_required
def organization_list(request):
    if not request.user.is_staff:
        return redirect('user_dashboard')  # Only admins can access this page

    organizations = Organization.objects.all()
    return render(request, 'qr_management/organization_list.html', {'organizations': organizations})

@login_required
def organization_create(request):
    if not request.user.is_staff:
        return redirect('user_dashboard')

    if request.method == 'POST':
        form = OrganizationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('organization_list')

    form = OrganizationForm()
    return render(request, 'qr_management/organization_form.html', {'form': form})

@login_required
def organization_edit(request, pk):
    if not request.user.is_staff:
        return redirect('user_dashboard')

    organization = get_object_or_404(Organization, pk=pk)
    if request.method == 'POST':
        form = OrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            form.save()
            return redirect('organization_list')

    form = OrganizationForm(instance=organization)
    return render(request, 'qr_management/organization_form.html', {'form': form})

@login_required
def organization_delete(request, pk):
    if not request.user.is_staff:
        return redirect('user_dashboard')

    organization = get_object_or_404(Organization, pk=pk)
    if request.method == 'POST':
        organization.delete()
        return redirect('organization_list')

    return render(request, 'qr_management/organization_confirm_delete.html', {'organization': organization})


@login_required
def home(request):
    if request.method == "POST":
        content = request.POST.get('content')
        if content:
            try:
                # Generate QR code
                qr = segno.make(content)
                buffer = io.BytesIO()
                qr.save(buffer, kind='png', scale=5)
                buffer.seek(0)
                qr_image = base64.b64encode(buffer.getvalue()).decode()

                # Save to database
                qr_code = QRCode.objects.create(
                    user=request.user,
                    qr_type='generic',
                    content=content,  # Save the original content
                    qr_image=qr_image  # Save the QR image data
                )

                return render(request, 'qr_management/home.html', {
                    'qr_code': qr_image,
                    'content': content,
                    'success': True
                })
            except Exception as e:
                print(f"QR Generation Error: {e}")  # For debugging
                return render(request, 'qr_management/home.html', {
                    'error': f"Failed to generate QR code: {str(e)}"
                })
    return render(request, 'qr_management/home.html')

@login_required
def vcard(request):
    if request.method == "POST":
        try:
            name = request.POST.get('name')
            email = request.POST.get('email', '')
            phone = request.POST.get('phone', '')
            company = request.POST.get('company', '')
            title = request.POST.get('title', '')
            address = request.POST.get('address', '')

            if not name:
                raise ValueError("Name is required")

            # Format vCard string
            vcard_string = f"""BEGIN:VCARD
VERSION:3.0
N:{name}
FN:{name}
{f'TEL:{phone}' if phone else ''}
{f'EMAIL:{email}' if email else ''}
{f'ORG:{company}' if company else ''}
{f'TITLE:{title}' if title else ''}
{f'ADR:{address}' if address else ''}
END:VCARD"""
            # Clean up empty lines
            vcard_string = '\n'.join(line for line in vcard_string.split('\n') if line.strip())
            
            # Save to database: Create QRCode with type 'vcard' and store vcard_string as content.
            qr_code = QRCode.objects.create(
                user=request.user,
                qr_type='vcard',
                content=vcard_string
            )
            # Save vCard details in the related model
            # (Assuming your QRVCard model fields match these names)
            QRVCard.objects.create(
                qr_code=qr_code,
                name=name,
                displayname=name,
                phone=phone,
                email=email,
                address=address,
                organization=company
            )
            
            # Build the redirection URL for analytics purposes
            relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
            redirection_url = request.build_absolute_uri(relative_url) + "?type=vcard"
            print(f"Generating vCard QR code with redirection URL: {redirection_url}")
            sys.stdout.flush()
            
            # Generate QR code using segno, with the redirection URL encoded
            qr = segno.make(redirection_url)
            buffer = io.BytesIO()
            qr.save(buffer, kind='png', scale=5)  # Adjust scale if needed
            buffer.seek(0)
            
            # Upload QR code image to Cloudinary
            qr_upload = cloudinary.uploader.upload(
                buffer,
                folder='qr_codes',
                public_id=f'vcard_{request.user.id}_{int(time.time())}'
            )
            qr_url = qr_upload.get('secure_url')
            if not qr_url:
                raise ValueError("Cloudinary did not return a secure URL for the QR code.")

            # Update the QRCode record with the uploaded image URL
            qr_code.cloudinary_url = qr_url
            qr_code.qr_image = qr_url
            qr_code.save(update_fields=['cloudinary_url', 'qr_image'])

            return render(request, 'qr_management/vcard.html', {
                'qr_image': qr_url,  # For display
                'qr_download': qr_url,  # For download button
            })

        except Exception as e:
            logger.error(f"vCard QR Generation Error: {str(e)}")
            return render(request, 'qr_management/vcard.html', {'error': str(e)})

    return render(request, 'qr_management/vcard.html')

@login_required
def mecard(request):
    if request.method == "POST":
        try:
            name = request.POST.get('name')
            phone = request.POST.get('phone', '')
            email = request.POST.get('email', '')
            address = request.POST.get('address', '')

            if not name:
                raise ValueError("Name is required")

            # Format MeCard string
            mecard_string = f"MECARD:N:{name};"
            if phone:
                mecard_string += f"TEL:{phone};"
            if email:
                mecard_string += f"EMAIL:{email};"
            if address:
                mecard_string += f"ADR:{address};"

            # Save to database: Create QRCode with type 'mecard' and store the MeCard string as content.
            qr_code = QRCode.objects.create(
                user=request.user,
                qr_type='mecard',
                content=mecard_string
            )
            # Save MeCard details to the QRMeCard model
            QRMeCard.objects.create(
                qr_code=qr_code,
                name=name,
                phone=phone,
                email=email,
                address=address
            )
            
            # Build the redirection URL for analytics purposes
            relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
            redirection_url = request.build_absolute_uri(relative_url) + "?type=mecard"
            print(f"Generating MeCard QR code with redirection URL: {redirection_url}")
            sys.stdout.flush()
            
            # Generate QR code using segno for the redirection URL
            qr = segno.make(redirection_url)
            buffer = io.BytesIO()
            qr.save(buffer, kind='png', scale=3)  # Adjust scale if needed
            buffer.seek(0)

            # Upload QR code image to Cloudinary
            qr_upload = cloudinary.uploader.upload(
                buffer,
                folder='qr_codes',
                public_id=f'mecard_{request.user.id}_{int(time.time())}'
            )
            qr_url = qr_upload.get('secure_url')
            if not qr_url:
                raise ValueError("Cloudinary did not return a secure URL for the QR code.")

            # Update the QRCode record with the uploaded image URL
            qr_code.cloudinary_url = qr_url
            qr_code.qr_image = qr_url
            qr_code.save(update_fields=['cloudinary_url', 'qr_image'])

            return render(request, 'qr_management/mecard.html', {
                'qr_image': qr_url,  # For display
                'qr_download': qr_url,  # For download button
            })

        except Exception as e:
            logger.error(f"MeCard QR Generation Error: {str(e)}")
            return render(request, 'qr_management/mecard.html', {'error': str(e)})

    return render(request, 'qr_management/mecard.html')
            

@login_required
def get_recent_qrcodes(request):
    try:
        recent_qrcodes = QRCode.objects.filter(user=request.user).order_by('-created_at')[:5]
        qrcodes_data = [{
            'qr_image': qr.qr_image,
            'qr_type': qr.qr_type,
            'created_at': qr.created_at.strftime('%Y-%m-%d %H:%M')
        } for qr in recent_qrcodes]
        
        return JsonResponse({
            'success': True,
            'qrcodes': qrcodes_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required

def email_qr(request):
    if request.method == "POST":
        form = EmailQRCodeForm(request.POST)
        if form.is_valid():
            try:
                # Get form data
                email = form.cleaned_data['email']
                subject = form.cleaned_data.get('subject', '')
                body = form.cleaned_data.get('body', '')

                # Format Email QR code string
                email_string = f"mailto:{email}"

                # Save the QR code object to the database
                qr_code = QRCode.objects.create(
                    user=request.user,
                    qr_type='email',
                    content=email_string
                )

                # Create and link the QREmail object
                QREmail.objects.create(
                    qr_code=qr_code,
                    recipient=email,
                    subject=subject,
                    body=body
                )

                # Generate the intermediate URL for the QR code
                redirect_url = request.build_absolute_uri(
                    reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
                )

                # Generate QR code for the intermediate URL
                qr = segno.make(redirect_url)
                buffer = io.BytesIO()
                qr.save(buffer, kind='png', scale=5)  # Adjust scale for smaller QR code
                buffer.seek(0)

                # Upload to Cloudinary
                cloudinary_response = cloudinary.uploader.upload(
                    buffer,
                    folder='qr_codes',
                    public_id=f'email_{request.user.id}_{int(time.time())}'
                )
                qr_url = cloudinary_response.get('secure_url')

                if not qr_url:
                    raise ValueError("Cloudinary did not return a secure URL for the QR code.")

                # Update the QR code object with the Cloudinary URL
                qr_code.cloudinary_url = qr_url
                qr_code.save()

                return render(request, 'qr_management/email.html', {
                    'qr_image': qr_url,  # Pass image URL for display
                    'qr_download': qr_url,  # Pass image URL for download button
                })

            except Exception as e:
                logger.error(f"Email QR Error: {str(e)}")
                return render(request, 'qr_management/email.html', {'form': form, 'error': str(e)})

    else:
        form = EmailQRCodeForm()

    return render(request, 'qr_management/email.html', {'form': form})

@login_required
def geo(request):
    if request.method == "POST":
        try:
            latitude = request.POST.get('latitude')
            longitude = request.POST.get('longitude')

            if not latitude or not longitude:
                raise ValueError("Both latitude and longitude are required")

            # Format the original geo string (store for record purposes)
            geo_string = f"geo:{latitude},{longitude}"

            # Create a QRCode record in the database with type 'geo' and content as the original geo string.
            qr_code = QRCode.objects.create(
                user=request.user,
                qr_type='geo',
                content=geo_string
            )

            # Build the absolute redirection URL for analytics.
            # This URL will point to your public redirection view and include a query parameter for qr_type.
            relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
            redirection_url = request.build_absolute_uri(relative_url) + "?type=geo"
            print(f"Generating Geo QR code with redirection URL: {redirection_url}")
            sys.stdout.flush()

            # Generate QR code image using segno with the redirection URL.
            qr = segno.make(redirection_url)
            buffer = io.BytesIO()
            qr.save(buffer, kind='png', scale=5)
            buffer.seek(0)

            # Upload the QR code image to Cloudinary.
            cloudinary_response = cloudinary.uploader.upload(
                buffer,
                folder='qr_codes',
                public_id=f'geo_{request.user.id}_{int(time.time())}'
            )
            qr_url = cloudinary_response.get('secure_url')
            if not qr_url:
                raise ValueError("Cloudinary did not return a secure URL for the QR code.")

            # Update the QRCode record with the Cloudinary URL.
            qr_code.cloudinary_url = qr_url
            qr_code.qr_image = qr_url
            qr_code.save(update_fields=['cloudinary_url', 'qr_image'])

            return render(request, 'qr_management/geo.html', {
                'qr_image': qr_url,  # For display
                'qr_download': qr_url  # For download link
            })

        except Exception as e:
            logger.error(f"Geo QR Generation Error: {str(e)}")
            return render(request, 'qr_management/geo.html', {'error': str(e)})

    return render(request, 'qr_management/geo.html')

@login_required
def wifi(request):
    if request.method == "POST":
        try:
            # Get form data
            ssid = request.POST.get('ssid')
            password = request.POST.get('password', '')
            encryption = request.POST.get('encryption', 'WPA')  # Default to WPA if not provided

            if not ssid:
                raise ValueError("SSID is required")

            # Format Wi-Fi string (this is stored for record purposes)
            wifi_string = f"WIFI:T:{encryption};S:{ssid};P:{password};;"

            # Create the QRCode record for type 'wifi'
            qr_code = QRCode.objects.create(
                user=request.user,
                qr_type='wifi',
                content=wifi_string
            )

            # Save Wi-Fi details to the QRWiFi model
            QRWiFi.objects.create(
                qr_code=qr_code,
                ssid=ssid,
                password=password,
                security=encryption
            )

            # Build the redirection URL for analytics:
            # This points to your public redirection view with a query parameter, e.g., ?type=wifi
            relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
            redirection_url = request.build_absolute_uri(relative_url) + "?type=wifi"
            print(f"Generating QR code with redirection URL: {redirection_url}")
            sys.stdout.flush()

            # Generate QR code image using segno with the redirection URL
            qr = segno.make(redirection_url)
            buffer = io.BytesIO()
            qr.save(buffer, kind='png', scale=5)  # Adjust scale as needed
            buffer.seek(0)

            # Upload the generated QR code image to Cloudinary
            cloudinary_response = cloudinary.uploader.upload(
                buffer.getvalue(),
                folder='qr_codes',
                public_id=f'wifi_{request.user.id}_{int(time.time())}'
            )
            qr_url = cloudinary_response.get('secure_url')
            if not qr_url:
                raise ValueError("Cloudinary did not return a secure URL for the QR code.")

            # Update the QRCode record with the Cloudinary URL
            qr_code.cloudinary_url = qr_url
            qr_code.qr_image = qr_url
            qr_code.save(update_fields=['cloudinary_url', 'qr_image'])

            return render(request, 'qr_management/wifi.html', {
                'qr_image': qr_url,      # For display
                'qr_download': qr_url,   # For download link
            })

        except Exception as e:
            logger.error(f"WiFi QR Generation Error: {str(e)}")
            return render(request, 'qr_management/wifi.html', {'error': str(e)})

    return render(request, 'qr_management/wifi.html')


def check_qr_status(request, qr_id):
    """
    API endpoint to check the status of a QR code generation
    """
    try:
        qr_code = QRCode.objects.get(id=qr_id)
        
        # If QR code exists but URL is not generated, try to generate it
        if not qr_code.cloudinary_url:
            qr_code.generate_and_upload_qr()
            qr_code.refresh_from_db()
        
        return JsonResponse({
            'id': qr_code.id,
            'cloudinary_url': qr_code.cloudinary_url,
            'status': 'complete' if qr_code.cloudinary_url else 'pending',
            'created_at': qr_code.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except QRCode.DoesNotExist:
        return JsonResponse({
            'error': 'QR code not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

@login_required
def generic(request):
    if request.method == "POST":
        form = GenericQRCodeForm(request.POST)
        if form.is_valid():
            try:
                content = form.cleaned_data['content']

                # Create the QRCode record for generic type
                qr_code = QRCode.objects.create(
                    user=request.user,
                    qr_type='generic',
                    content=content
                )

                # Optionally, create a related QRGeneric record if needed:
                # QRGeneric.objects.create(qr_code=qr_code, content=content)

                # Build the redirection URL for analytics:
                # This URL will point to your public redirection view and include the qr_type parameter.
                relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
                redirection_url = request.build_absolute_uri(relative_url) + "?type=generic"
                print(f"Generating Generic QR code with redirection URL: {redirection_url}")
                sys.stdout.flush()

                # Generate the QR code image using segno with the redirection URL
                qr = segno.make(redirection_url)
                buffer = io.BytesIO()
                qr.save(buffer, kind='png', scale=5)  # Adjust scale as needed
                buffer.seek(0)

                # Convert image to base64 for inline display (or use Cloudinary upload if preferred)
                qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
                qr_data = f"data:image/png;base64,{qr_base64}"

                # Optionally update the QRCode record with the generated QR image data
                qr_code.qr_image = qr_data  # If you wish to store base64; otherwise, upload to Cloudinary
                qr_code.save(update_fields=['qr_image'])

                return render(request, 'qr_management/generic.html', {
                    'qr_image': qr_data,      # For inline display
                    'qr_download': qr_data,   # For download link (if you wish to provide this)
                })

            except Exception as e:
                logger.error(f"Generic QR Generation Error: {str(e)}")
                return render(request, 'qr_management/generic.html', {'form': form, 'error': str(e)})
        else:
            print(form.errors)
            sys.stdout.flush()
    else:
        form = GenericQRCodeForm()

    return render(request, 'qr_management/generic.html', {'form': form})


@login_required
def pdf_qr(request):
    if request.method == "POST":
        form = PDFQRCodeForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                # Upload the PDF and get its secure URL.
                pdf_file = request.FILES['pdf_file']
                pdf_upload = cloudinary.uploader.upload(
                    pdf_file,
                    resource_type='raw',
                    folder='pdf_uploads'
                )
                pdf_url = pdf_upload.get('secure_url')
                if not pdf_url:
                    raise ValueError("Cloudinary did not return a secure URL for the PDF.")
                
                # Save the QRCode object with the PDF URL as its content.
                qr_code = QRCode.objects.create(
                    user=request.user,
                    qr_type='pdf',
                    content=pdf_url
                )

                # Save PDF details to the QRPDF model.
                QRPDF.objects.create(
                    qr_code=qr_code,
                    pdf_file=pdf_upload.get('public_id', ''),
                    title=form.cleaned_data['title'],
                    description=form.cleaned_data.get('description', '')
                )

                # Generate an intermediate URL for the QR code redirect.
                redirect_url = request.build_absolute_uri(
                    reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
                )

                # Generate the QR code image for the intermediate URL.
                qr = segno.make(redirect_url)
                buffer = BytesIO()
                qr.save(buffer, kind="png", scale=5)
                buffer.seek(0)

                # Upload the QR code image to Cloudinary.
                qr_upload = cloudinary.uploader.upload(
                    buffer,
                    folder='pdf_qr_codes',
                    public_id=f'pdf_{request.user.id}_{int(time.time())}'
                )
                qr_url = qr_upload.get('secure_url')
                if not qr_url:
                    raise ValueError("Cloudinary did not return a secure URL for the QR code.")

                # Update the QRCode object with the Cloudinary URL.
                qr_code.cloudinary_url = qr_url
                qr_code.save()

                return render(request, 'qr_management/pdf.html', {
                    'form': PDFQRCodeForm(),
                    'qr_image': qr_url,  # QR code image URL for display/download.
                    'pdf_url': pdf_url   # PDF file URL.
                })

            except Exception as e:
                logger.error(f"PDF QR Error: {str(e)}")
                return render(request, 'qr_management/pdf.html', {'form': form, 'error': str(e)})
        else:
            return render(request, 'qr_management/pdf.html', {'form': form})
    else:
        form = PDFQRCodeForm()
    return render(request, 'qr_management/pdf.html', {'form': form})


@login_required

def url_qr(request):
    if request.method == "POST":
        try:
            # Get form data
            url = request.POST.get('url')
            title = request.POST.get('title', '')

            if not url:
                raise ValueError("URL is required")

            # Store the original URL in the content field
            # Create the QRCode object for type 'url'
            qr_code = QRCode.objects.create(
                user=request.user,
                qr_type='url',
                content=url
            )
            
            # Save URL details to the QRUrl model
            QRUrl.objects.create(
                qr_code=qr_code,
                url=url,
                title=title
            )
            
            # Build the redirection URL for analytics: it points to your public redirection view and includes the qr_type
            relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
            redirection_url = request.build_absolute_uri(relative_url) + "?type=url"
            print(f"Generating QR code with redirection URL: {redirection_url}")
            sys.stdout.flush()
            
            # Generate QR code image using segno with the redirection URL
            qr = segno.make(redirection_url)
            buffer = io.BytesIO()
            qr.save(buffer, kind='png', scale=5)  # Adjust scale as needed
            buffer.seek(0)

            # Upload the generated QR code image to Cloudinary
            cloudinary_response = cloudinary.uploader.upload(
                buffer,
                folder='qr_codes',
                public_id=f'url_{request.user.id}_{int(time.time())}'
            )
            qr_url = cloudinary_response.get('secure_url')
            if not qr_url:
                raise ValueError("Cloudinary did not return a secure URL for the QR code.")

            # Update the QRCode object with the Cloudinary URL
            qr_code.cloudinary_url = qr_url
            qr_code.qr_image = qr_url
            qr_code.save(update_fields=['cloudinary_url', 'qr_image'])

            return render(request, 'qr_management/url.html', {
                'qr_image': qr_url,  # For display
                'qr_download': qr_url,  # For download link
            })

        except Exception as e:
            logger.error(f"URL QR Generation Error: {str(e)}")
            return render(request, 'qr_management/url.html', {'error': str(e)})

    return render(request, 'qr_management/url.html')

@login_required
def social_media_qr(request):
    if request.method == "POST":
        form = SocialMediaQRCodeForm(request.POST)
        if form.is_valid():
            try:
                # Save the QRCode object using the form with the user provided
                qr_code = form.save(user=request.user)  # Pass user here
                qr_code.qr_type = 'social_media'
                qr_code.save()

                # Build the redirection URL for analytics:
                relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
                redirection_url = request.build_absolute_uri(relative_url) + "?type=social_media"
                print(f"Generating QR code with redirection URL: {redirection_url}")
                sys.stdout.flush()

                # Generate QR code image using segno with the redirection URL
                qr = segno.make(redirection_url)
                buffer = io.BytesIO()
                qr.save(buffer, kind="png", scale=5)
                buffer.seek(0)

                # Upload the generated QR code image to Cloudinary
                cloudinary_response = cloudinary.uploader.upload(
                    buffer.getvalue(),
                    folder="social_qrs",
                    public_id=f'social_{request.user.id}_{int(time.time())}'
                )
                qr_url = cloudinary_response.get('secure_url')
                if not qr_url:
                    raise ValueError("Cloudinary did not return a secure URL for the QR code.")

                # Update the QRCode object with the Cloudinary URL
                qr_code.cloudinary_url = qr_url
                qr_code.qr_image = qr_url
                qr_code.save(update_fields=['cloudinary_url', 'qr_image'])

                return render(request, 'qr_management/social_media.html', {
                    'qr_image': qr_url,
                    'qr_download': qr_url
                })

            except Exception as e:
                logger.error(f"Social Media QR Error: {str(e)}")
                return render(request, 'qr_management/social_media.html', {'form': form, 'error': str(e)})
    else:
        form = SocialMediaQRCodeForm()
    return render(request, 'qr_management/social_media.html', {'form': form})
@login_required
def logo_qr(request):
    if request.method == "POST":
        form = LogoQRCodeForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                # Check if the logo file is present
                if 'logo' in request.FILES:
                    logo_file = request.FILES['logo']
                    print(f"Logo File: {logo_file}")
                    sys.stdout.flush()
                else:
                    print("No logo file uploaded.")
                    sys.stdout.flush()
                    raise ValueError("Logo file not uploaded.")

                # Save the QRCode object using the form (without committing yet)
                qr_code = form.save(request.user, commit=False)
                qr_code.user = request.user
                qr_code.qr_type = 'logo'
                qr_code.save()

                # Upload the logo image to Cloudinary and update the QRCode record
                logo_response = cloudinary.uploader.upload(request.FILES['logo'], folder="qr_logos")
                logo_url = logo_response.get('secure_url')
                if not logo_url:
                    raise ValueError("Cloudinary did not return a secure URL for the logo.")
                qr_code.cloudinary_url = logo_url
                qr_code.save(update_fields=['cloudinary_url'])

                # Build the redirection URL for analytics: 
                # It points to your public redirection view with a query parameter, e.g., ?type=logo
                relative_url = reverse('qr_redirect', kwargs={'qr_id': qr_code.id})
                redirection_url = request.build_absolute_uri(relative_url) + "?type=logo"
                print(f"Generating QR code with redirection URL: {redirection_url}")
                sys.stdout.flush()

                # Generate a QR code image using segno with the redirection URL
                qr = segno.make(redirection_url)
                buffer = io.BytesIO()
                qr.save(buffer, kind="png", scale=5)
                buffer.seek(0)
                qr_pil = Image.open(buffer)

                # Fetch the logo image from Cloudinary using the logo URL
                logo_resp = requests.get(logo_url)
                logo_img = Image.open(io.BytesIO(logo_resp.content))

                # Resize and overlay the logo onto the QR code image
                qr_width, qr_height = qr_pil.size
                desired_logo_width = int(qr_width * 0.25)
                aspect_ratio = logo_img.height / logo_img.width
                desired_logo_height = int(desired_logo_width * aspect_ratio)
                logo_img = logo_img.resize((desired_logo_width, desired_logo_height), Image.Resampling.LANCZOS)

                # Calculate position to center the logo on the QR code
                x_pos = (qr_width - desired_logo_width) // 2
                y_pos = (qr_height - desired_logo_height) // 2

                # Overlay the logo onto the QR code image, preserving transparency if available
                if logo_img.mode in ('RGBA', 'LA'):
                    qr_pil.paste(logo_img, (x_pos, y_pos), logo_img)
                else:
                    qr_pil.paste(logo_img, (x_pos, y_pos))

                # Save the final QR code image to a BytesIO buffer
                output_buffer = io.BytesIO()
                qr_pil.save(output_buffer, format="PNG")
                output_buffer.seek(0)

                # Upload the final QR code image to Cloudinary
                final_upload = cloudinary.uploader.upload(
                    output_buffer.getvalue(),
                    folder="qr_logos",
                    public_id=f'logo_{request.user.id}_{int(time.time())}'
                )
                final_qr_url = final_upload.get('secure_url')
                if not final_qr_url:
                    raise ValueError("Cloudinary did not return a secure URL for the final QR code.")

                # Update the QRCode object with the final QR code image URL
                qr_code.qr_image = final_qr_url
                qr_code.save(update_fields=['qr_image'])

                return render(request, 'qr_management/logo.html', {
                    'qr_image': final_qr_url,      # For display
                    'qr_download': final_qr_url,   # For download link
                })

            except Exception as e:
                logger.error(f"Logo QR Error: {str(e)}")
                return render(request, 'qr_management/logo.html', {'form': form, 'error': str(e)})

    else:
        form = LogoQRCodeForm()

    return render(request, 'qr_management/logo.html', {'form': form})

def send_ga4_event(client_id, event_name, params, measurement_id="G-LL04F1XF5C", api_secret="6ds4MDQFSUq--HbwW02dog"):
    """
    Sends a custom event to GA4 using the Measurement Protocol.
    """
    endpoint = (
        f"https://www.google-analytics.com/mp/collect"
        f"?measurement_id={measurement_id}&api_secret={api_secret}"
    )

    params['debug_mode'] = True
    payload = {
        "client_id": client_id,
        "events": [
            {
                "name": event_name,
                "params": params,
            }
        ]
    }
    logger.info("Sending POST request to: %s", endpoint)
    logger.info("Payload: %s", payload)
    # Log the payload to verify user_id inclusion
    logger.info("GA4 Payload: %s", json.dumps(payload, indent=2))
    response = requests.post(endpoint, json=payload)
    logger.info("Response Status Code: %s", response.status_code)
    logger.info("Response Text: %s", response.text)
    return response.status_code, response.text


def qr_redirect(request, qr_id):
    """
    Django view that handles a QR code scan:
      - Captures scan details (timestamp, IP, user agent, device OS, and location if possible)
      - Sends a custom event ("qr_scan") to GA4 using the Measurement Protocol
      - Redirects the user to the QR code's destination URL or performs the encoded action
    """
    qr_code = get_object_or_404(QRCode, id=qr_id)

    # Capture the current scan time
    scan_time = timezone.now().isoformat()

    # Retrieve user agent and IP address from request headers
    user_agent_str = request.META.get('HTTP_USER_AGENT', '')
    ip_address = request.META.get('REMOTE_ADDR', '')

    # Determine device OS using user_agents if available, otherwise fallback
    if ua_available:
        ua = user_agents.parse(user_agent_str)
        device_os = ua.os.family  # e.g., "iOS", "Android", "Windows"
    else:
        device_os = "Unknown OS"

    # Determine device location using GeoIP2 if available, otherwise fallback
    if geo_available:
        try:
            geo = GeoIP2()
            location = geo.city(ip_address)
            device_location = f"{location.get('city', 'Unknown')}, {location.get('region', 'Unknown')}, {location.get('country_name', 'Unknown')}"
        except Exception:
            device_location = "Unknown"
    else:
        device_location = "Unknown"

    # Generate or retrieve a persistent client_id (from a cookie if available)
    client_id = request.COOKIES.get('client_id', str(uuid.uuid4()))

    # Send the QR scan event to GA4
    event_params = {
        "scan_time": scan_time,
        "user_agent": user_agent_str,
        "ip_address": ip_address,
        "device_os": device_os,
        "device_location": device_location,
        "qr_id": qr_id,
        "scan_count": qr_code.scan_count,
    }
    
    event_params['qr_type'] = qr_code.qr_type  # Add qr_type to the event parameters

    # Add username to event parameters, or use 'anonymous' if the user is not authenticated
    event_params['username'] = request.user.username if request.user.is_authenticated else 'anonymous'
    
    print("DEBUG: GA4 Event Payload:", event_params)
    import sys
    sys.stdout.flush()
    status, response_text = send_ga4_event(client_id, "qr_scan", event_params)
    logger.info(f"GA4 Event Status: {status}, Response: {response_text}")

    # Handle different QR code types
    if qr_code.qr_type == "email":
        email_details = qr_code.email_details
        mailto_link = f"mailto:{email_details.recipient}?subject={email_details.subject}&body={email_details.body}"
        return HttpResponse(f'<html><head><meta http-equiv="refresh" content="0;url={mailto_link}" /></head><body></body></html>')

    elif qr_code.qr_type == "url":
        return redirect(qr_code.content)  # Redirect to the URL

    elif qr_code.qr_type == "pdf":
        return redirect(qr_code.content)  # Redirect to the PDF URL

    elif qr_code.qr_type == "social_media":
        return redirect(qr_code.content)  # Redirect to the social media URL

    elif qr_code.qr_type == "logo":
        # For logo, check if the stored content is a safe URL
        if qr_code.content.startswith("http"):
            return HttpResponseRedirect(qr_code.content)
        else:
            # If not a valid URL, render an HTML page to display the content.
            html_content = f"""
                <html>
                    <head>
                        <title>Logo QR Information</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            pre {{ background-color: #f4f4f4; padding: 10px; border: 1px solid #ddd; }}
                        </style>
                    </head>
                    <body>
                        <h2>Logo QR Code Information</h2>
                        <p>The following data was encoded in the QR code:</p>
                        <pre>{qr_code.content}</pre>
                        <p>Please copy this information as needed.</p>
                    </body>
                </html>
            """
            return HttpResponse(html_content, content_type="text/html")


    elif qr_code.qr_type == "generic":
        # If content is a valid URL, redirect; otherwise, render the content.
        if qr_code.content.startswith("http"):
            return HttpResponseRedirect(qr_code.content)
        else:
            html_content = f"""
                <html>
                    <head>
                        <title>Generic QR Code Content</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        </style>
                    </head>
                    <body>
                        <h2>Generic QR Code Content</h2>
                        <p>{qr_code.content}</p>
                    </body>
                </html>
            """
            return HttpResponse(html_content, content_type="text/html")
    
    elif qr_code.qr_type == "vcard":
        # Instead of redirecting, render an HTML page displaying vCard details.
        html_content = f"""
            <html>
                <head>
                    <title>vCard Information</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        pre {{ background-color: #f4f4f4; padding: 10px; border: 1px solid #ddd; }}
                    </style>
                </head>
                <body>
                    <h2>vCard Information</h2>
                    <p>The following vCard data was encoded in the QR code:</p>
                    <pre>{qr_code.content}</pre>
                    <p>You can copy this information to add the contact details to your device.</p>
                </body>
            </html>
        """
        return HttpResponse(html_content, content_type="text/html")
    
    elif qr_code.qr_type == "mecard":
        # Render an HTML page displaying MeCard details.
        html_content = f"""
            <html>
                <head>
                    <title>MeCard Information</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        pre {{ background-color: #f4f4f4; padding: 10px; border: 1px solid #ddd; }}
                    </style>
                </head>
                <body>
                    <h2>MeCard Information</h2>
                    <p>The following MeCard data was encoded in the QR code:</p>
                    <pre>{qr_code.content}</pre>
                    <p>You can copy this information to add the contact details to your device.</p>
                </body>
            </html>
        """
        return HttpResponse(html_content, content_type="text/html")
    elif qr_code.qr_type == "geo":
        # Instead of redirecting to a raw geo URL, render an HTML page that displays the geo data.
        # Expect qr_code.content to be in the format "geo:latitude,longitude"
        if qr_code.content.startswith("geo:"):
            coordinates = qr_code.content[4:]
        else:
            coordinates = qr_code.content
        html_content = f"""
            <html>
                <head>
                    <title>Geo Location</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    </style>
                </head>
                <body>
                    <h2>Geo Location</h2>
                    <p>Coordinates: {coordinates}</p>
                    <p><a href="https://maps.google.com/?q={coordinates}">View on Google Maps</a></p>
                </body>
            </html>
        """
        return HttpResponse(html_content, content_type="text/html")
    
    elif qr_code.qr_type == "wifi":
        try:
            # Retrieve Wi-Fi details from the related QRWiFi model
            wifi_details = qr_code.wifi_details
            ssid = wifi_details.ssid
            security = wifi_details.security
            password = wifi_details.password or ""
            # Build the standard Wi-Fi configuration string
            wifi_string = f"WIFI:T:{security};S:{ssid};P:{password};;"
        except Exception as e:
            logger.error(f"Error retrieving WiFi details for QRCode id {qr_id}: {str(e)}")
            wifi_string = qr_code.content  # fallback

        # Since browsers cannot directly redirect to a "WIFI:" protocol URL,
        # render an HTML page with a clickable link that attempts to trigger the connection.
        html_content = f"""
            <html>
                <head>
                    <title>Connect to Wi-Fi</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body>
                    <h2>Wi-Fi Configuration</h2>
                    <p>Please use the following details to connect to the Wi-Fi network:</p>
                    <pre>{wifi_string}</pre>
                    <p>If your device supports automatic connection, <a href="{wifi_string}">click here to connect</a>.</p>
                    <p>If nothing happens, please manually enter the network details.</p>
                </body>
            </html>
        """
        return HttpResponse(html_content, content_type="text/html")
    else:
        if qr_code.content.startswith("http"):
            return HttpResponseRedirect(qr_code.content)
        else:
            return HttpResponse(f"<html><body><p>{qr_code.content}</p></body></html>", content_type="text/html")


    # Ensure the correct URL is used for Cloudinary upload
    if not qr_code.cloudinary_url:
        analytics_url = request.build_absolute_uri(reverse('qr_redirect', kwargs={'qr_id': qr_code.id}))
        qr_code.generate_and_upload_qr(analytics_url)
        qr_code.refresh_from_db()

    # For other QR codes, use the content field as the destination URL
    response = redirect(qr_code.content)

    # Store client_id in a cookie for persistence (set for one year)
    response.set_cookie('client_id', client_id, max_age=365*24*60*60)
    return response
@login_required
def analytics_dashboard(request):
    return render(request, 'qr_management/analytics_dashboard.html')