from django import forms
from django.contrib.auth import get_user_model
from .models import (
    QRCode, Organization, QRWiFi, QRGeo, QRVCard, QRMeCard, QREmail, QRGeneric
)

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
    Provides common fields like error correction, scale, border, and colors.
    These fields can be used for customizing the generated QR code image.
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
    dark_color = forms.CharField(
        label="Dark Color",
        initial="#000000",
        widget=forms.TextInput(attrs={'type': 'color'}),
        required=False
    )
    light_color = forms.CharField(
        label="Light Color",
        initial="#FFFFFF",
        widget=forms.TextInput(attrs={'type': 'color'}),
        required=False
    )


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


class EmailQRCodeForm(QRCodeGenerationForm):
    """
    Form for generating Email QR codes.
    """
    recipient = forms.EmailField(label="Recipient Email")
    subject = forms.CharField(label="Subject", max_length=255, required=False)
    body = forms.CharField(label="Body", widget=forms.Textarea(attrs={'rows': 4}), required=False)

    def save(self, user, commit=True):
        qr_code = QRCode(user=user, qr_type='email')

        if commit:
            qr_code.save()
            qr_email = QREmail(
                qr_code=qr_code,
                recipient=self.cleaned_data['recipient'],
                subject=self.cleaned_data.get('subject', ''),
                body=self.cleaned_data.get('body', '')
            )
            qr_email.save()
            qr_code.content = qr_code.generate_content()
            qr_code.save(update_fields=['content'])
        return qr_code




class GenericQRCodeForm(QRCodeGenerationForm):
    """
    Form for generating Generic QR codes (e.g., URL or free text).
    """
    url = forms.URLField(label="URL", max_length=2083, required=False)
    content = forms.CharField(
        label="Content",
        widget=forms.Textarea(attrs={'rows': 4}),
        required=False
    )

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
