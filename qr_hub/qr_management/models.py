from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models

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
        default=10.00,  # Default QR code generation quota
        help_text="The maximum number of QR codes the user can create."
    )
    qr_codes_created = models.PositiveIntegerField(
        default=0,  # Default number of QR codes created is 0
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

        Returns:
            int: Remaining QR code quota.
        """
        if self.qr_quota<=0:
            raise ValidationError("You have Exhausted your quota limit.")
        else:
            return max(self.qr_quota - self.qr_codes_created, 0)

    def __str__(self):
        return self.username


class QRCode(models.Model):
    QR_TYPES = [
        ("email", "Email"),
        ("geo", "Geo Location"),
        ("generic", "Generic"),
        ("mecard", "MeCard"),
        ("vcard", "VCard"),
        ("wifi", "WiFi"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="qrcodes",
        help_text="The user who created this QR code.",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="qr_codes",
        help_text="The organization associated with this QR code.",
    )
    qr_type = models.CharField(max_length=20, choices=QR_TYPES)
    created_at = models.DateTimeField(auto_now_add=True)
    content = models.TextField(blank=True, null=True, help_text="Generated content for the QR code.")

def generate_content(self):
    """
    Generates the content based on the qr_type and associated detail model.
    """
    qr_type = self.qr_type
    data = ''

    try:
        if qr_type == 'email':
            details = self.email_details  # Access the related QREmail instance
            recipient = details.recipient
            subject = details.subject
            body = details.body
            data = f"MATMSG:TO:{recipient};SUB:{subject};BODY:{body};;"

        elif qr_type == 'geo':
            details = self.geo_details  # Access the related QRGeo instance
            latitude = details.latitude
            longitude = details.longitude
            data = f"geo:{latitude},{longitude}"

        elif qr_type == 'generic':
            details = self.generic_details  # Access the related QRGeneric instance
            data = details.content

        elif qr_type == 'mecard':
            details = self.mecard_details  # Access the related QRMeCard instance
            name = details.name
            phone = details.phone
            email = details.email
            address = details.address or ''
            data = f"MECARD:N:{name};TEL:{phone};EMAIL:{email};ADR:{address};;"

        elif qr_type == 'vcard':
            details = self.vcard_details  # Access the related QRVCard instance
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
            details = self.wifi_details  # Access the related QRWiFi instance
            ssid = details.ssid
            password = details.password or ''
            security = details.security
            data = f"WIFI:T:{security};S:{ssid};P:{password};;"

        else:
            data = ''

    except (QREmail.DoesNotExist, QRGeo.DoesNotExist, QRGeneric.DoesNotExist,
            QRMeCard.DoesNotExist, QRVCard.DoesNotExist, QRWiFi.DoesNotExist):
        # If the related detail object does not exist, return an empty string
        data = ''
    return data

def __str__(self):
    return f"QR Code ({self.qr_type}) by {self.user.username}"


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