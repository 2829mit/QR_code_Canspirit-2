from django import forms
from django.contrib.auth import get_user_model
import cloudinary
import cloudinary.uploader
import cloudinary.api
from .models import (
    QRCode, Organization, QRWiFi, QRGeo, QRVCard, QRMeCard, QREmail, QRGeneric, QRPDF, QRUrl, QRSocialMedia, QRLogo
)
from qr_management.models import QRCode, Organization, QRWiFi, QRGeo, QRVCard, QRMeCard, QREmail, QRGeneric, QRPDF, QRUrl, QRSocialMedia, QRLogo
import logging

logger = logging.getLogger(__name__)    

User = get_user_model()


class OrganizationForm(forms.ModelForm):
    """
    Form for creating or updating an organization.
    """
    class Meta:
        model = Organization
        fields = ['name', 'address']


class UserRegistrationForm(forms.ModelForm):
    """
    Form for user registration.
    Includes fields for username, email, password, and password confirmation.
    """
    password = forms.CharField(
        widget=forms.PasswordInput,
        label="Password"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Confirm Password"
    )

    class Meta:
        model = User
        fields = ['username', 'email']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match!")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
        return user


class QRCodeGenerationForm(forms.Form):
    """
    Base form for QR code generation.
    """
    error_correction = forms.ChoiceField(
        label="Error Correction",
        choices=[('L', 'L (7%)'), ('M', 'M (15%)'), ('Q', 'Q (25%)'), ('H', 'H (30%)')],
        initial='M',
        required=True
    )
    scale = forms.IntegerField(
        label="Scale",
        min_value=1,
        max_value=10,
        initial=5,
        required=True
    )
    border = forms.IntegerField(
        label="Border",
        min_value=1,
        max_value=10,
        initial=4,
        required=True
    )
    
    content = forms.CharField(required=False)
    url = forms.URLField(required=False)
    border = forms.IntegerField(required=False, initial=4)

    def generate_qr_image(self, data):
        """Generates a QR code image and uploads it to Cloudinary."""
        import qrcode
        from io import BytesIO
        import cloudinary.uploader

        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            border=self.cleaned_data.get("border", 4),
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")

        buffer.seek(0)  # Move to the start of the file
        response = cloudinary.uploader.upload(buffer, folder="qr_codes/")  # Upload to Cloudinary

        return response.get("secure_url")  # Return the Cloudinary image URL

    def save(self, user, commit=True):
        """
        Saves the QR code instance with the Cloudinary URL.
        """
        qr_code = QRCode(user=user, qr_type='generic')
        qr_content = self.cleaned_data.get("content") or self.cleaned_data.get("url")
        qr_code.content = qr_content

        if commit:
            qr_code.save()
           

            '''qr_code.cloudinary_url = cloudinary_url  # Store the Cloudinary URL
            qr_code.content = qr_content
            qr_code.save(update_fields=['content', 'cloudinary_url'])'''

        return qr_code

class WiFiQRCodeForm(QRCodeGenerationForm):
    """
    Form for generating WiFi QR codes.
    """
    ssid = forms.CharField(label="WiFi SSID", max_length=100)
    password = forms.CharField(label="WiFi Password", widget=forms.PasswordInput, required=False)
    security = forms.ChoiceField(
        label="Encryption Type",
        choices=[('WPA', 'WPA'), ('WEP', 'WEP'), ('WPA2', 'WPA2'), ('None', 'None')],
        initial='WPA'
    )
    hidden = forms.BooleanField(label="Hidden Network", required=False)

    def save(self, user, commit=True):
        # Create QRCode instance without saving to database yet
        qr_code = QRCode(user=user, qr_type='wifi')

        if commit:
            qr_code.save()
            # Create QRWiFi instance
            qr_wifi = QRWiFi(
                qr_code=qr_code,
                ssid=self.cleaned_data['ssid'],
                password=self.cleaned_data.get('password'),
                security=self.cleaned_data['security']
            )
            qr_wifi.save()
            # Now that the detail instance is saved, generate and save content
            qr_code.content = qr_code.generate_content()
            qr_code.save(update_fields=['content'])
        return qr_code

class GeoQRCodeForm(QRCodeGenerationForm):
    """
    Form for generating Geo Location QR codes.
    """
    latitude = forms.DecimalField(label="Latitude", max_digits=9, decimal_places=6)
    longitude = forms.DecimalField(label="Longitude", max_digits=9, decimal_places=6)

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='geo')

        if commit:
            qr_code.save()
            qr_geo = QRGeo(
                qr_code=qr_code,
                latitude=self.cleaned_data['latitude'],
                longitude=self.cleaned_data['longitude']
            )
            qr_geo.save()
            qr_code.content = qr_code.generate_content()
            qr_code.save(update_fields=['content'])
        return qr_code

class VCardQRCodeForm(QRCodeGenerationForm):
    """
    Form for generating vCard QR codes.
    """
    name = forms.CharField(label="Name", max_length=100)
    displayname = forms.CharField(label="Display Name", max_length=100)
    phone = forms.CharField(label="Phone", max_length=20)
    email = forms.EmailField(label="Email")
    address = forms.CharField(label="Address", max_length=255)
    organization = forms.CharField(label="Organization", max_length=100)

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='vcard')

        if commit:
            qr_code.save()
            qr_vcard = QRVCard(
                qr_code=qr_code,
                name=self.cleaned_data['name'],
                displayname=self.cleaned_data['displayname'],
                phone=self.cleaned_data['phone'],
                email=self.cleaned_data['email'],
                address=self.cleaned_data['address'],
                organization=self.cleaned_data['organization']
            )
            qr_vcard.save()
            qr_code.content = qr_code.generate_content()
            qr_code.save(update_fields=['content'])
        return qr_code

class MeCardQRCodeForm(QRCodeGenerationForm):
    """
    Form for generating MeCard QR codes.
    """
    name = forms.CharField(label="Name", max_length=100)
    phone = forms.CharField(label="Phone", max_length=20)
    email = forms.EmailField(label="Email")
    address = forms.CharField(label="Address", max_length=255, required=False)

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='mecard')

        if commit:
            qr_code.save()
            qr_mecard = QRMeCard(
                qr_code=qr_code,
                name=self.cleaned_data['name'],
                phone=self.cleaned_data['phone'],
                email=self.cleaned_data['email'],
                address=self.cleaned_data.get('address'),
            )
            qr_mecard.save()
            qr_code.content = qr_code.generate_content()
            qr_code.save(update_fields=['content'])
        return qr_code


class EmailQRCodeForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    subject = forms.CharField(required=False)
    body = forms.CharField(widget=forms.Textarea, required=False)

    class Meta:
        model = QREmail
        fields = ['email', 'subject', 'body']

    def save(self, user):
        qr_code = QRCode.objects.create(
            user=user,
            qr_type='email',
            content=f"mailto:{self.cleaned_data['email']}?subject={self.cleaned_data['subject']}&body={self.cleaned_data['body']}"
        )
        QREmail.objects.create(
            qr_code=qr_code,
            email=self.cleaned_data['email'],
            subject=self.cleaned_data['subject'],
            body=self.cleaned_data['body']
        )
        return qr_code




class GenericQRCodeForm(QRCodeGenerationForm):
    url = forms.URLField(label="URL", max_length=2083, required=False)
    content = forms.CharField(
        label="Content",
        widget=forms.Textarea(attrs={'rows': 4}),
        required=False
    )
    # Override error_correction and scale with default values and mark them as not required
    error_correction = forms.CharField(initial='L', required=False)
    scale = forms.IntegerField(initial=5, required=False)

    def clean(self):
        cleaned_data = super().clean()
        url = cleaned_data.get('url')
        content = cleaned_data.get('content')
        if not url and not content:
            raise forms.ValidationError("Please provide either a URL or some content.")
        return cleaned_data

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='generic')

        if commit:
            qr_code.save()
            qr_generic = QRGeneric(
                qr_code=qr_code,
                content=self.cleaned_data.get('content')
            )
            qr_generic.save()
            qr_code.content = qr_code.generate_content()
            qr_code.save(update_fields=['content'])
        return qr_code


class PDFQRCodeForm(forms.ModelForm):
    pdf_file = forms.FileField(required=True)
    title = forms.CharField(max_length=255, required=True)
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = QRPDF
        fields = ['pdf_file', 'title', 'description']

    def save(self, user):
        # Upload PDF to Cloudinary
        pdf = self.cleaned_data['pdf_file']
        upload_result = cloudinary.uploader.upload(
            pdf,
            resource_type = "raw",
            folder = "pdf_uploads"
        )
        
        # Create QR Code entry
        qr_code = QRCode.objects.create(
            user=user,
            qr_type='pdf',
            content=upload_result['secure_url'],
            cloudinary_url=upload_result['secure_url']
        )
        
        # Create PDF entry
        QRPDF.objects.create(
            qr_code=qr_code,
            pdf_file=upload_result['public_id'],
            title=self.cleaned_data['title'],
            description=self.cleaned_data['description']
        )
        
        return qr_code

class URLQRCodeForm(forms.ModelForm):
    url = forms.URLField(max_length=2083, required=True)
    title = forms.CharField(max_length=255, required=False)

    class Meta:
        model = QRUrl
        fields = ['url', 'title']

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='url')
        if commit:
            qr_code.save()
            qr_url = QRUrl(qr_code=qr_code, url=self.cleaned_data['url'], title=self.cleaned_data.get('title'))
            qr_url.save()
            qr_code.content = self.cleaned_data['url']
            qr_code.save(update_fields=['content'])
        return qr_code

class SocialMediaQRCodeForm(forms.ModelForm):
    platform = forms.ChoiceField(choices=QRSocialMedia.PLATFORM_CHOICES)
    username = forms.CharField(max_length=255)
    url = forms.URLField(max_length=2083)

    class Meta:
        model = QRSocialMedia
        fields = ['platform', 'username', 'url']

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='social')
        if commit:
            qr_code.save()
            qr_social = QRSocialMedia(qr_code=qr_code, platform=self.cleaned_data['platform'],
                                       username=self.cleaned_data['username'], url=self.cleaned_data['url'])
            qr_social.save()
            qr_code.content = self.cleaned_data['url']
            qr_code.save(update_fields=['content'])
        return qr_code

class LogoQRCodeForm(forms.ModelForm):
    logo = forms.ImageField(label="Logo Image")
    content = forms.CharField(widget=forms.Textarea, help_text="Content to encode in the QR code")
    background_color = forms.CharField(max_length=7, initial='#FFFFFF', widget=forms.TextInput(attrs={'type': 'color'}))
    foreground_color = forms.CharField(max_length=7, initial='#000000', widget=forms.TextInput(attrs={'type': 'color'}))

    class Meta:
        model = QRLogo
        fields = ['logo', 'content', 'background_color', 'foreground_color']

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='logo')
        if commit:
            qr_code.save()

            # Upload the logo to Cloudinary
            if self.cleaned_data.get('logo'):
                logo_response = cloudinary.uploader.upload(self.cleaned_data['logo'], folder="qr_logos")
                logo_url = logo_response.get('secure_url')

                # Save the QRLogo object and associate with the QRCode
                qr_logo = QRLogo(qr_code=qr_code, logo=logo_url,
                                 content=self.cleaned_data['content'],
                                 background_color=self.cleaned_data['background_color'],
                                 foreground_color=self.cleaned_data['foreground_color'])
                qr_logo.save()

                # Update the QR code object with the content and Cloudinary URL
                qr_code.content = self.cleaned_data['content']
                qr_code.cloudinary_url = logo_url  # Store the Cloudinary URL of the logo
                qr_code.save(update_fields=['content', 'cloudinary_url'])
        return qr_code
