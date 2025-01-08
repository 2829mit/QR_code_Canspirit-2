from io import BytesIO
import os
import qrcode
import re
from django.db import transaction
from django.utils import timezone
import segno
import base64
import io
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db.models import Count, F
from django.http import JsonResponse, HttpResponseForbidden, FileResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpRequest
import segno.helpers
from .forms import UserRegistrationForm,OrganizationForm,WiFiQRCodeForm, GeoQRCodeForm, VCardQRCodeForm, MeCardQRCodeForm, EmailQRCodeForm
from .models import (
    QRCode, Organization, QRGeneric, QRVCard, QRMeCard,
    QREmail, QRGeo, QRWiFi

)

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
    user = request.user  # Get the current user
    qr_codes = QRCode.objects.filter(user=user)  # Retrieve the QR codes created by the user

    organization_qr_codes = []

    if user.organization:
        organization_qr_codes = QRCode.objects.filter(organization=user.organization)

    # Prepare the context to be passed to the template
    context = {
        'welcome_message': f"Welcome, {user.username}!",  # Display a personalized welcome message
        'qr_codes_created': user.qrcodes.count(),  # Show the number of QR codes created by the user
        'remaining_quota': user.remaining_quota(),  # Display the user's remaining QR code quota
        'qr_codes': qr_codes,  # Pass the user's generated QR codes to the template
        'organization_qr_codes': organization_qr_codes,
        'organization': user.organization,
    }

    # Render the user dashboard template with the user's data
    return render(request, 'qr_management/user_dashboard.html',context)


@login_required  # Ensure the user is logged in before accessing this view
def user_view_qrcodes(request):
    """
    Displays the QR codes created by the logged-in user. Handles both regular and AJAX requests.

    For AJAX requests, only the list of QR codes is rendered, while for regular requests, 
    the full page with QR codes is rendered.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A rendered template with the user's QR codes.
    """
    # Fetch the QR codes belonging to the logged-in user
    user = request.user
    personal_qr_codes = QRCode.objects.filter(user=user)
    organization_qr_codes = QRCode.objects.filter(organization=user.organization) if user.organization else []
    context = {
        'personal_qr_codes': personal_qr_codes,
        'organization_qr_codes': organization_qr_codes,
        'organization': user.organization,
    }

    # Handle AJAX requests separately (render partial template for QR code list)
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return render(request, 'qr_management/partials/user_qr_list.html', context)
    
    # For non-AJAX requests, render the full page with QR codes
    return render(request, 'qr_management/user_view_qrcodes.html', context)


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



@login_required  # Ensure that the user is logged in before accessing this view
def user_dashboard_data(request):
    """
    Fetches and renders the QR codes created by the logged-in user for their dashboard.

    This view is designed to handle the request for displaying a list of QR codes 
    created by the user in their dashboard, either as a full page or through AJAX requests 
    (depending on the implementation).

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A rendered partial template containing the list of QR codes for the user.
    """
    # Fetch the QR codes created by the logged-in user
    user = request.user
    personal_qr_codes = QRCode.objects.filter(user=user)
    organization_qr_codes = QRCode.objects.filter(organization=user.organization) if user.organization else []
    context = {
        'personal_qr_codes': personal_qr_codes,
        'organization_qr_codes': organization_qr_codes,
        'organization': user.organization,
    }

    # Render and return the partial template for the user's QR code list
    return render(request, 'qr_management/partials/user_qr_list.html', context)

# Function to sanitize filenames
def sanitize_filename(content):
    """
    This function sanitizes the content by removing any characters 
    that are not allowed in filenames (e.g., ':' on Windows).
    """
    return re.sub(r'[<>:"/\\|?*]', '_', content)

@login_required  # Ensure that the user is logged in before accessing this view
def generate_qr_code(request):
    """
    Handles QR code generation for the logged-in user based on the type selected.
    This view checks if the user has remaining quota for creating QR codes and processes
    the form to generate and save a new QR code for the selected type.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A redirection to the user dashboard if successful or a rendered page
        showing quota exceeded message if the user has no remaining quota.
    """
    # Debugging: Check if the user has exceeded their QR code generation quota
    print(f"Remaining quota for user {request.user.id}: {request.user.remaining_quota()}")

    if request.user.remaining_quota() <= 0:
        return render(request, 'qr_management/quota_exceeded.html')

    # Handle form submission
    if request.method == 'POST':
        # Debugging: Check if any QR code type was selected
        print(f"POST data received: {request.POST}")

        if 'wifi' in request.POST:
            form = WiFiQRCodeForm(request.POST)
        elif 'geo' in request.POST:
            form = GeoQRCodeForm(request.POST)
        elif 'vcard' in request.POST:
            form = VCardQRCodeForm(request.POST)
        elif 'mecard' in request.POST:
            form = MeCardQRCodeForm(request.POST)
        elif 'email' in request.POST:
            form = EmailQRCodeForm(request.POST)
        else:
            form = None

        # Debugging: Check if form is valid and display errors if not
        if form and form.is_valid():
            content = form.cleaned_data['content']

            # Sanitize the content for filename (only first 10 characters)
            sanitized_content = sanitize_filename(content[:10])
            
            # Generate the QR code using the selected content
            qr = qrcode.QRCode(
                version=1,  # Size of the QR code
                error_correction=qrcode.constants.ERROR_CORRECT_L,  # Error correction level
                box_size=10,  # Size of each box in the QR code
                border=4,  # Border width
            )
            qr.add_data(content)  # Add the content to the QR code
            qr.make(fit=True)  # Ensure the QR code fits the content
            
            # Create the image for the QR code
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()  # Use a buffer to store the image in memory
            img.save(buffer)  # Save the image into the buffer
            buffer.seek(0)  # Reset the buffer position to the start
            
            # Generate a sanitized filename and save the image to the database
            qr_image = ContentFile(buffer.read(), name=f"qr_{request.user.id}_{sanitized_content}.png")
            
            # Save the generated QR code into the database
            QRCode.objects.create(user=request.user, content=content, image=qr_image, organization=request.user.organization)
            
            # Update the user's QR code creation count
            request.user.qr_codes_created += 1
            request.user.save()
            
            # Redirect the user to their dashboard after successful QR code creation
            return redirect('user_dashboard')
        else:
            # Debugging: Print form errors if form is not valid
            print(f"Form errors: {form.errors}")

    else:
        # Initially, no form submitted
        form = None

    # Debugging: Ensure we are rendering the template with the form
    print("Rendering generate_qr.html with form context")

    # Render the QR code generation page with the appropriate form
    return render(request, 'qr_management/generate_qr.html', {'form': form})

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

    Args:
        request (HttpRequest): The HTTP request object.
        qr_id (int): The ID of the QR code to be downloaded.

    Returns:
        FileResponse: A response that prompts the user to download the QR code image.
    """
    # Retrieve the QR code by its ID, raise 404 if not found
    qr_code = get_object_or_404(QRCode, id=qr_id)

    # Ensure that only the owner or an admin can download the QR code
    if qr_code.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("You do not have permission to download this QR code.")

    # Generate the QR code data based on the type and associated detail model
    qr_data = get_qr_data(qr_code)

    # Generate the QR code image
    qr_image = generate_qr_image(qr_data)

    # Prepare the image for response
    img_io = io.BytesIO()
    qr_image.save(img_io, format='PNG')
    img_io.seek(0)

    # Set up FileResponse
    filename = f"qr_code_{qr_code.id}.png"
    response = FileResponse(img_io, as_attachment=True, filename=filename)
    response['Content-Type'] = 'image/png'
    return response

def get_qr_data(qr_code):
    """
    Generate the data string for the QR code based on its type and associated data.
    """
    qr_type = qr_code.qr_type
    data = ''

    if qr_type == 'email':
        details = qr_code.email_details
        recipient = details.recipient
        subject = details.subject
        body = details.body
        data = f"MATMSG:TO:{recipient};SUB:{subject};BODY:{body};;"

    elif qr_type == 'geo':
        details = qr_code.geo_details
        latitude = details.latitude
        longitude = details.longitude
        data = f"geo:{latitude},{longitude}"

    elif qr_type == 'generic':
        details = qr_code.generic_details
        data = details.content

    elif qr_type == 'mecard':
        details = qr_code.mecard_details
        name = details.name
        phone = details.phone
        email = details.email
        address = details.address or ''
        data = f"MECARD:N:{name};TEL:{phone};EMAIL:{email};ADR:{address};;"

    elif qr_type == 'vcard':
        details = qr_code.vcard_details
        name = details.name
        displayname = details.displayname
        phone = details.phone
        email = details.email
        address = details.address
        organization = details.organization
        data = (
            "BEGIN:VCARD\n"
            "VERSION:3.0\n"
            f"FN:{displayname}\n"
            f"N:{name}\n"
            f"ORG:{organization}\n"
            f"TEL:{phone}\n"
            f"EMAIL:{email}\n"
            f"ADR:{address}\n"
            "END:VCARD"
        )

    elif qr_type == 'wifi':
        details = qr_code.wifi_details
        ssid = details.ssid
        password = details.password or ''
        security = details.security
        data = f"WIFI:T:{security};S:{ssid};P:{password};;"
    else:
        data = ''

    return data

def generate_qr_image(data):
    """
    Generates a QR code image from the data string.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    return img

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


def home(request):
    """
    Handles the QR code generation for the home page.
    This view renders the form, processes the form submission,
    generates a QR code, saves it to the database, and displays it on the page.
    """
    qr_image = None  # To store the generated QR code image

    if request.method == 'POST':
        try:
            # Get form data directly from POST
            content = request.POST.get('content')
            error_correction = request.POST.get('error-correction')
            scale = int(request.POST.get('scale', 5))
            border = int(request.POST.get('border', 1))
            dark_color = request.POST.get('dark', '#000000')
            light_color = request.POST.get('light', '#FFFFFF')

            # Set QR code error correction level
            error_correction_levels = {
                'L': qrcode.constants.ERROR_CORRECT_L,
                'M': qrcode.constants.ERROR_CORRECT_M,
                'Q': qrcode.constants.ERROR_CORRECT_Q,
                'H': qrcode.constants.ERROR_CORRECT_H
            }
            error_correction_level = error_correction_levels.get(error_correction, qrcode.constants.ERROR_CORRECT_M)

            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=error_correction_level,
                box_size=scale,
                border=border
            )
            qr.add_data(content)
            qr.make(fit=True)

            # Create image for QR code
            img = qr.make_image(fill_color=dark_color, back_color=light_color)

            # Convert image to base64 encoding for embedding in HTML
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            qr_image = base64.b64encode(buffer.getvalue()).decode()

            # Save QR code data to the database
            with transaction.atomic():
                # Create QRCode instance
                qr_code = QRCode(
                    user=request.user if request.user.is_authenticated else None,
                    organization=request.user.organization if request.user.is_authenticated and request.user.organization else None,
                    qr_type='generic',
                    created_at=timezone.now()
                )
                qr_code.save()

                # Create QRGeneric instance
                qr_generic = QRGeneric(
                    qr_code=qr_code,
                    content=content
                )
                qr_generic.save()

                # Update user's QR code count if the user is authenticated
                if request.user.is_authenticated:
                    request.user.qr_codes_created = request.user.qrcodes.count()
                    request.user.save()

            return render(request, 'qr_management/home.html', {
                'qr_image': qr_image
            })
        except Exception as e:
            print(f"QR Code Generation Error: {e}")
    return render(request, "qr_management/home.html")

def vcard(request):
    """
    Handles vCard QR code generation, saves data to the database,
    and displays the generated QR code.
    """
    v_code = None
    if request.method == "POST":
        try:
            full_name = request.POST.get("full_name")
            displayname = request.POST.get("full_name")
            organization = request.POST.get("organization", "")
            email = request.POST.get("email", "")
            phone = request.POST.get("phone", "")
            address = request.POST.get("address", "")
            url = request.POST.get("url", "")

            # Generate vCard QR Code using segno
            qr = segno.helpers.make_vcard(
                name=full_name,
                displayname=displayname,
                org=organization,
                email=email,
                phone=phone,
                street=address,
                url=url,
            )

            # Save QR code data to the database
            with transaction.atomic():
                # Create QRCode instance
                qr_code = QRCode(
                    user=request.user if request.user.is_authenticated else None,
                    organization=request.user.organization if request.user.is_authenticated and request.user.organization else None,
                    qr_type='vcard',
                    created_at=timezone.now()
                )
                qr_code.save()

                # Create QRVCard instance
                qr_vcard = QRVCard(
                    qr_code=qr_code,
                    name=full_name,
                    displayname=displayname,
                    phone=phone,
                    email=email,
                    address=address,
                    organization=organization
                )
                qr_vcard.save()

                # Update user's QR code count if the user is authenticated
                if request.user.is_authenticated:
                    request.user.qr_codes_created = request.user.qrcodes.count()
                    request.user.save()

            buffer = io.BytesIO()

            qr.save(
                buffer,
                kind='png',
                scale=5,
            )
            # Convert to base64
            v_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

            return render(request, "qr_management/vcard.html", {"qr_code": v_code})

        except Exception as e:
            print(f"QR Code Generation Error: {e}")
    return render(request, "qr_management/vcard.html")

def mecard(request):
    """
    Handles MeCard QR code generation, saves data to the database,
    and displays the generated QR code.
    """
    me_code = None
    if request.method == "POST":
        try:
            name = request.POST.get('full_name')
            phone = request.POST.get('phone')
            email = request.POST.get('email')
            organization = request.POST.get('organization', '')
            url = request.POST.get('url', '')

            # Generate MeCard QR Code using segno
            qr = segno.helpers.make_mecard(
                name=name,
                phone=phone,
                email=email,
                url=url,
            )

            # Save QR code data to the database
            with transaction.atomic():
                # Create QRCode instance
                qr_code = QRCode(
                    user=request.user if request.user.is_authenticated else None,
                    organization=request.user.organization if request.user.is_authenticated and request.user.organization else None,
                    qr_type='mecard',
                    created_at=timezone.now()
                )
                qr_code.save()

                # Create QRMeCard instance
                qr_mecard = QRMeCard(
                    qr_code=qr_code,
                    name=name,
                    phone=phone,
                    email=email,
                )
                qr_mecard.save()

                # Update user's QR code count if the user is authenticated
                if request.user.is_authenticated:
                    request.user.qr_codes_created = request.user.qrcodes.count()
                    request.user.save()

            buffer = io.BytesIO()

            qr.save(
                buffer,
                kind='png',
                scale=5,
            )
            # Convert to base64
            me_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

            return render(request, "qr_management/mecard.html", {'qr_code': me_code})

        except Exception as e:
            print(f"QR Code Generation Error: {e}")
    return render(request, "qr_management/mecard.html")

def email(request):
    """
    Handles Email QR code generation, saves data to the database,
    and displays the generated QR code.
    """
    email_code = None
    if request.method == "POST":
        try:
            recipient = request.POST.get("recipient")
            subject = request.POST.get("subject", "")
            body = request.POST.get("body", "")

            # Generate Email QR Code using segno
            qr = segno.helpers.make_email(to=recipient, subject=subject, body=body)

            # Save QR code data to the database
            with transaction.atomic():
                # Create QRCode instance
                qr_code = QRCode(
                    user=request.user if request.user.is_authenticated else None,
                    organization=request.user.organization if request.user.is_authenticated and request.user.organization else None,
                    qr_type='email',
                    created_at=timezone.now()
                )
                qr_code.save()

                # Create QREmail instance
                qr_email = QREmail(
                    qr_code=qr_code,
                    recipient=recipient,
                    subject=subject,
                    body=body
                )
                qr_email.save()

                # Update user's QR code count if the user is authenticated
                if request.user.is_authenticated:
                    request.user.qr_codes_created = request.user.qrcodes.count()
                    request.user.save()

            buffer = io.BytesIO()

            qr.save(
                buffer,
                kind='png',
                scale=5,
            )
            # Convert to base64
            email_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

            return render(request, "qr_management/email.html", {"qr_code": email_code})

        except Exception as e:
            print(f"QR Code Generation Error: {e}")

    return render(request, "qr_management/email.html")

def geo(request):
    """
    Handles Geo Location QR code generation, saves data to the database,
    and displays the generated QR code.
    """
    geo_code = None

    if request.method == 'POST':
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')

        try:
            # Validate latitude and longitude
            lat = float(latitude)
            lon = float(longitude)

            # Create geo URI for QR Code
            geo_uri = f"geo:{lat},{lon}"

            # Generate QR Code using segno
            qr = segno.make(geo_uri)

            # Save QR code data to the database
            with transaction.atomic():
                # Create QRCode instance
                qr_code = QRCode(
                    user=request.user if request.user.is_authenticated else None,
                    organization=request.user.organization if request.user.is_authenticated and request.user.organization else None,
                    qr_type='geo',
                    created_at=timezone.now()
                )
                qr_code.save()

                # Create QRGeo instance
                qr_geo = QRGeo(
                    qr_code=qr_code,
                    latitude=lat,
                    longitude=lon
                )
                qr_geo.save()

                # Update user's QR code count if the user is authenticated
                if request.user.is_authenticated:
                    request.user.qr_codes_created = request.user.qrcodes.count()
                    request.user.save()

            # Save QR Code to a bytes buffer
            buffer = io.BytesIO()
            qr.save(buffer, kind='png', scale=5)

            # Encode the QR Code to base64 for HTML display
            geo_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

            return render(request, "qr_management/geo.html", {"qr_code": geo_code})

        except Exception as e:
            print(f"QR Code Generation Error: {e}")

    return render(request, "qr_management/geo.html")

def wifi(request):
    """
    Handles WiFi QR code generation, saves data to the database,
    and displays the generated QR code.
    """
    wifi_code = None
    if request.method == "POST":
        try:
            ssid = request.POST.get("ssid")
            password = request.POST.get("password")
            security = request.POST.get("security", "WPA")
            hidden = request.POST.get("hidden", "off") == "on"

            # Generate WiFi QR Code using segno
            qr = segno.helpers.make_wifi(ssid=ssid, password=password, security=security, hidden=hidden)

            # Save QR code data to the database
            with transaction.atomic():
                # Create QRCode instance
                qr_code = QRCode(
                    user=request.user if request.user.is_authenticated else None,
                    organization=request.user.organization if request.user.is_authenticated and request.user.organization else None,
                    qr_type='wifi',
                    created_at=timezone.now()
                )
                qr_code.save()

                # Create QRWiFi instance
                qr_wifi = QRWiFi(
                    qr_code=qr_code,
                    ssid=ssid,
                    password=password,
                    security=security
                )
                qr_wifi.save()

                # Update user's QR code count if the user is authenticated
                if request.user.is_authenticated:
                    request.user.qr_codes_created = request.user.qrcodes.count()
                    request.user.save()

            buffer = io.BytesIO()

            qr.save(
                buffer,
                kind='png',
                scale=5,
            )

            # Convert to base64
            wifi_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

            return render(request, "qr_management/wifi.html", {"qr_code": wifi_code})

        except Exception as e:
            print(f"QR Code Generation Error: {e}")

    return render(request, "qr_management/wifi.html")
