import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from qr_management.forms import (
    PDFQRCodeForm,
    EmailQRCodeForm,
    LogoQRCodeForm,
    SocialMediaQRCodeForm,
    URLQRCodeForm,            # Assuming this is your URLQRCodeForm
    VCardQRCodeForm,      # For vCard
    MeCardQRCodeForm,
    WiFiQRCodeForm,
    GeoQRCodeForm,
    GenericQRCodeForm,
)

# -------------------------------------------------------------------
# Helper: A minimal valid PNG (1x1 pixel transparent)


# -------------------------------------------------------------------
# PDFQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_pdf_qr_form_valid():
    pdf_file = SimpleUploadedFile("sample.pdf", b"%PDF-1.4 dummy content", content_type="application/pdf")
    form_data = {'title': 'Test PDF Title', 'description': 'Optional description'}
    file_data = {'pdf_file': pdf_file}
    form = PDFQRCodeForm(data=form_data, files=file_data)
    assert form.is_valid(), f"Errors: {form.errors}"

@pytest.mark.django_db
def test_pdf_qr_form_invalid():
    # Missing pdf_file field should make the form invalid.
    form = PDFQRCodeForm(data={'title': 'Test Title', 'description': 'Optional description'})
    assert not form.is_valid(), "PDFQRCodeForm should be invalid if pdf_file is missing"

# -------------------------------------------------------------------
# EmailQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_email_qr_form_valid():
    form_data = {
        'email': 'test@example.com',
        'subject': 'Test Subject',
        'body': 'This is a test message.'
    }
    form = EmailQRCodeForm(data=form_data)
    assert form.is_valid(), f"Errors: {form.errors}"

@pytest.mark.django_db
def test_email_qr_form_invalid():
    # Invalid email address.
    form_data = {
        'email': 'not-an-email',
        'subject': 'Test Subject',
        'body': 'Test message'
    }
    form = EmailQRCodeForm(data=form_data)
    assert not form.is_valid(), "EmailQRCodeForm should be invalid with a bad email"

# -------------------------------------------------------------------
# LogoQRCodeForm Tests
# -------------------------------------------------------------------
def test_logo_qr_form_valid():
    # Read the image file from disk in binary mode
    with open(r"C:\Users\suryansh\OneDrive\Desktop\qr_code_1 (2).png", "rb") as f:
        valid_png = f.read()
    
    image_file = SimpleUploadedFile("logo.png", valid_png, content_type="image/png")
    form_data = {
        'content': 'Test QR Content',
        'background_color': '#FFFFFF',
        'foreground_color': '#000000'
    }
    file_data = {'logo': image_file}
    form = LogoQRCodeForm(data=form_data, files=file_data)
    # Uncomment the line below to debug form errors if needed:
    # print(form.errors)
    assert form.is_valid(), f"LogoQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_logo_qr_form_invalid():
    # Missing logo field should cause the form to be invalid.
    form_data = {
        'content': 'Test QR Content',
        'background_color': '#FFFFFF',
        'foreground_color': '#000000'
    }
    form = LogoQRCodeForm(data=form_data)
    assert not form.is_valid(), "LogoQRCodeForm should be invalid if logo is missing"

# -------------------------------------------------------------------
# SocialMediaQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_social_media_qr_form_valid():
    form_data = {
        'platform': 'facebook',
        'username': 'testuser',
        'url': 'https://facebook.com/testuser'
    }
    form = SocialMediaQRCodeForm(data=form_data)
    assert form.is_valid(), f"SocialMediaQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_social_media_qr_form_invalid():
    # Missing 'username'
    form_data = {
        'platform': 'facebook',
        'url': 'https://facebook.com/testuser'
    }
    form = SocialMediaQRCodeForm(data=form_data)
    assert not form.is_valid(), "SocialMediaQRCodeForm should be invalid if username is missing"

# -------------------------------------------------------------------
# QRUrlForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_qr_url_form_valid():
    form_data = {
        'url': 'https://example.com',
        'title': 'Example Site'
    }
    form = URLQRCodeForm(data=form_data)
    assert form.is_valid(), f"QRUrlForm errors: {form.errors}"

@pytest.mark.django_db
def test_qr_url_form_invalid():
    # URL is required; an empty URL should fail.
    form_data = {'url': ''}
    form = URLQRCodeForm(data=form_data)
    assert not form.is_valid(), "QRUrlForm should be invalid if URL is empty"

# -------------------------------------------------------------------
# VCardQRCodeForm Tests (vCard)
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_vcard_form_valid():
    form_data = {
        'name': 'John',
        'displayname': 'John Doe',
        'phone': '1234567890',
        'email': 'john@example.com',
        'address': '123 Main St',
        'organization': 'Test Org',
        # Additional fields from QRCodeGenerationForm:
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'vCard content',
        'url': 'https://example.com'
    }
    form = VCardQRCodeForm(data=form_data)
    assert form.is_valid(), f"VCardQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_vcard_form_invalid():
    # Missing required field: name.
    form_data = {
        'displayname': 'John Doe',
        'phone': '1234567890',
        'email': 'john@example.com',
        'address': '123 Main St',
        'organization': 'Test Org',
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'vCard content',
        'url': 'https://example.com'
    }
    form = VCardQRCodeForm(data=form_data)
    assert not form.is_valid(), "VCardQRCodeForm should be invalid if name is missing"

# -------------------------------------------------------------------
# MeCardQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_mecard_form_valid():
    form_data = {
        'name': 'John Doe',
        'phone': '1234567890',
        'email': 'john@example.com',
        'address': '123 Main St',
        # Required inherited fields:
        'error_correction': 'M',  # assuming valid values are e.g., L, M, Q, H
        'scale': 5,
        'border': 4,
        'content': 'MeCard content'
    }
    form = MeCardQRCodeForm(data=form_data)
    assert form.is_valid(), f"MeCardQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_mecard_form_invalid():
    # Missing required field: name.
    form_data = {
        'phone': '1234567890',
        'email': 'john@example.com',
        'address': '123 Main St',
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'MeCard content'
    }
    form = MeCardQRCodeForm(data=form_data)
    assert not form.is_valid(), "MeCardQRCodeForm should be invalid if name is missing"


# -------------------------------------------------------------------
# WiFiQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_wifi_form_valid():
    form_data = {
        'ssid': 'MyNetwork',
        'password': 'mypassword',
        'security': 'WPA',
        'hidden': False,
        # Include base QR fields if necessary:
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'WiFi content'
    }
    form = WiFiQRCodeForm(data=form_data)
    assert form.is_valid(), f"WiFiQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_wifi_form_invalid():
    # Missing required field: ssid.
    form_data = {
        'password': 'mypassword',
        'security': 'WPA',
        'hidden': False,
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'WiFi content'
    }
    form = WiFiQRCodeForm(data=form_data)
    assert not form.is_valid(), "WiFiQRCodeForm should be invalid if ssid is missing"

# -------------------------------------------------------------------
# GeoQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_geo_form_valid():
    form_data = {
        'latitude': '12.345678',
        'longitude': '98.765432',
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'Geo content'
    }
    form = GeoQRCodeForm(data=form_data)
    assert form.is_valid(), f"GeoQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_geo_form_invalid():
    # Missing required field: longitude.
    form_data = {
        'latitude': '12.345678',
        'error_correction': 'M',
        'scale': 5,
        'border': 4,
        'content': 'Geo content'
    }
    form = GeoQRCodeForm(data=form_data)
    assert not form.is_valid(), "GeoQRCodeForm should be invalid if longitude is missing"

# -------------------------------------------------------------------
# GenericQRCodeForm Tests
# -------------------------------------------------------------------
@pytest.mark.django_db
def test_generic_qr_form_valid():
    form_data = {
        'content': 'Some generic content',
        'url': 'https://example.com',  # At least one must be provided.
        'error_correction': 'L',
        'scale': 5,
        'border': 4,
    }
    form = GenericQRCodeForm(data=form_data)
    assert form.is_valid(), f"GenericQRCodeForm errors: {form.errors}"

@pytest.mark.django_db
def test_generic_qr_form_invalid():
    # Both 'content' and 'url' missing should cause the form to be invalid.
    form_data = {
        'content': '',
        'url': '',
        'error_correction': 'L',
        'scale': 5,
        'border': 4,
    }
    form = GenericQRCodeForm(data=form_data)
    assert not form.is_valid(), "GenericQRCodeForm should be invalid if both content and url are missing"
