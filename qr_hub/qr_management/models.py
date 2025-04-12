from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from cloudinary.models import CloudinaryField
from django.contrib.auth import get_user_model
from django.utils import timezone
import logging
import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model



class Organization(models.Model):
    name = models.CharField(max_length=100, unique=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class User(AbstractUser):
    """
    Custom user model extending AbstractUser to include additional fields.
    """
    qr_quota = models.IntegerField(
        default=10,  # Must be an integer
        help_text="The maximum number of QR codes the user can create."
    )
    qr_codes_created = models.PositiveIntegerField(
        default=0,
        help_text="The number of QR codes the user has created."
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="members",
        help_text="The organization to which the user belongs."
    )

    def remaining_quota(self):
        """
        Calculates the remaining quota for QR code generation.
        Ensures the value is not negative.
        """
        remaining = max(self.qr_quota - self.qr_codes_created, 0)
        if remaining <= 0:
            raise ValidationError("You have exhausted your quota limit.")
        return remaining

    def __str__(self):
        return self.username

# Now, get the User model after defining it
User = get_user_model()

import cloudinary.uploader
from io import BytesIO
import qrcode

logger=logging.getLogger(__name__)

class MediumTextField(models.TextField):
    def db_type(self, connection):
        engine = connection.settings_dict.get('ENGINE', '').lower()
        if 'mysql' in engine:
            return 'mediumtext'
        return super().db_type(connection)

class QRCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name='qrcodes')
    qr_type = models.CharField(max_length=20)
    content = models.TextField()  # Stores the actual content/URL
    qr_image =  models.URLField(blank=True, null=True, max_length=4096) # Cloudinary URL for QR image
    cloudinary_url = models.URLField(max_length=1000,blank=True, null=False)  # For PDF/files
    logo = models.ImageField(upload_to='logos/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    scan_count = models.IntegerField(default=0)

    # Related fields for different QR code types
    '''wifi_details = models.OneToOneField('QRWiFi', on_delete=models.CASCADE, null=True, blank=True, related_name='qr_code')
    geo_details = models.OneToOneField('QRGeo', on_delete=models.CASCADE, null=True, blank=True, related_name='qr_code')
    email_details = models.OneToOneField('QREmail', on_delete=models.CASCADE, null=True, blank=True, related_name='qr_code')
    mecard_details = models.OneToOneField('QRMeCard', on_delete=models.CASCADE, null=True, blank=True, related_name='qr_code')
    vcard_details = models.OneToOneField('QRVCard', on_delete=models.CASCADE, null=True, blank=True, related_name='qr_code')'''

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username}'s {self.qr_type} QR"

    def get_qr_url(self):
        return self.cloudinary_url if self.cloudinary_url else None
    def clean(self):
        if self.qr_image and len(self.qr_image) > 4096:
            raise ValidationError("The length of the qr_image URL exceeds the maximum allowed length of 4096 characters.")
    def increment_scan_count(self):
        self.scan_count += 1
        self.save(update_fields=['scan_count']) 
    def generate_and_upload_qr(self, redirect_url):
        """
        Generates a QR code image for the given redirect URL and uploads it to Cloudinary.
        Returns the secure URL of the uploaded image if successful, or None otherwise.
        """
        # Create a QRCode object from the qrcode library
        qr = qrcode.QRCode(
            version=1,  # controls the size of the QR Code; use higher numbers for more data
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        # Add the redirect URL to the QR code data
        qr.add_data(redirect_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save the image to a BytesIO stream
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        # Upload the image to Cloudinary
        try:
            upload_result = cloudinary.uploader.upload(buffer, folder="qrcodes")
            secure_url = upload_result.get("secure_url")
            # Update the cloudinary_url and qr_image fields with the uploaded image URL
            self.cloudinary_url = secure_url
            self.qr_image = secure_url
            self.save(update_fields=["cloudinary_url", "qr_image"])
            return secure_url
        except Exception as e:
            logger.exception("Failed to upload QR code to Cloudinary: %s", e)
            return None   
        
class QRScanEvent(models.Model):
    qr_code = models.ForeignKey(QRCode, on_delete=models.CASCADE, related_name='scan_events')
    scan_time = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    device_os = models.CharField(max_length=100, blank=True, null=True)
    device_location = models.CharField(max_length=255, blank=True, null=True)
    client_id = models.CharField(max_length=50, blank=True, null=True)  # For GA4 unique tracking

    class Meta:
        ordering = ['-scan_time']

    def __str__(self):
        return f"Scan for QR {self.qr_code.id} at {self.scan_time}"

# ---------------------------------------
#  QR Code Type-Specific Models
# ---------------------------------------

class QREmail(models.Model):
    qr_code = models.OneToOneField(
        QRCode,
        on_delete=models.CASCADE,
        related_name="email_details",
        help_text="Related QR code for email type.",
    )
    recipient = models.CharField(max_length=100)
    subject = models.CharField(max_length=255)
    body = models.TextField()


class QRGeo(models.Model):
    qr_code = models.OneToOneField(
        QRCode,
        on_delete=models.CASCADE,
        related_name="geo_details",
        help_text="Related QR code for geo-location type.",
    )
    latitude = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)


class QRGeneric(models.Model):
    qr_code = models.OneToOneField(
        QRCode,
        on_delete=models.CASCADE,
        related_name="generic_details",
        help_text="Related QR code for generic type.",
    )
    content = models.TextField(blank=True, null=True)


class QRMeCard(models.Model):
    qr_code = models.OneToOneField(
        QRCode,
        on_delete=models.CASCADE,
        related_name="mecard_details",
        help_text="Related QR code for MeCard type.",
    )
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    email = models.EmailField(max_length=100)
    address = models.CharField(max_length=255, blank=True, null=True)


class QRVCard(models.Model):
    qr_code = models.OneToOneField(
        QRCode,
        on_delete=models.CASCADE,
        related_name="vcard_details",
        help_text="Related QR code for vCard type.",
    )
    name = models.CharField(max_length=100)
    displayname = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    email = models.EmailField(max_length=100)
    address = models.CharField(max_length=255)
    organization = models.CharField(max_length=100)


class QRWiFi(models.Model):
    SECURITY_CHOICES = [
        ("WEP", "WEP"),
        ("WPA", "WPA"),
        ("WPA2", "WPA2"),
        ("None", "None"),
    ]

    qr_code = models.OneToOneField(
        QRCode,
        on_delete=models.CASCADE,
        related_name="wifi_details",
        help_text="Related QR code for WiFi type.",
    )
    ssid = models.CharField(max_length=100)
    password = models.CharField(max_length=100, blank=True, null=True)
    security = models.CharField(max_length=10, choices=SECURITY_CHOICES)

class QRPDF(models.Model):
    qr_code = models.OneToOneField(QRCode, on_delete=models.CASCADE, related_name="pdf_details")
    pdf_file = models.FileField(upload_to='pdf_files/')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

class QRUrl(models.Model):
    qr_code = models.OneToOneField(QRCode, on_delete=models.CASCADE, related_name="url_details")
    url = models.URLField(max_length=2083)
    title = models.CharField(max_length=255, blank=True, null=True)

class QRSocialMedia(models.Model):
    PLATFORM_CHOICES = [
        ('facebook', 'Facebook'),
        ('twitter', 'Twitter'),
        ('instagram', 'Instagram'),
        ('linkedin', 'LinkedIn'),
        ('youtube', 'YouTube'),
        ('tiktok', 'TikTok'),
    ]
    qr_code = models.OneToOneField(QRCode, on_delete=models.CASCADE, related_name="social_media_details")
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    username = models.CharField(max_length=255)
    url = models.URLField(max_length=2083)

class QRLogo(models.Model):
    qr_code = models.OneToOneField(QRCode, on_delete=models.CASCADE, related_name="logo_details")
    logo = CloudinaryField('logo')
    content = models.TextField()
    background_color = models.CharField(max_length=7, default='#FFFFFF')
    foreground_color = models.CharField(max_length=7, default='#000000')
