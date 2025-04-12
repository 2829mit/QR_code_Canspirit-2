import pytest
from django.core.exceptions import ValidationError
from qr_management.models import Organization, QRCode, User

@pytest.mark.django_db
def test_organization_str():
    org = Organization.objects.create(name="Acme Inc.", address="123 Acme Road")
    assert str(org) == "Acme Inc."

@pytest.mark.django_db
def test_user_remaining_quota(user):
    # When qr_codes_created is 0 and quota is 10, remaining should be 10
    remaining = user.remaining_quota()
    assert remaining == 10

    # Simulate user using some quota
    user.qr_codes_created = 7
    user.save()
    remaining = user.remaining_quota()
    assert remaining == 3

    # If quota is exhausted, remaining_quota() should raise ValidationError
    user.qr_codes_created = 10
    user.save()
    with pytest.raises(ValidationError):
        user.remaining_quota()

@pytest.mark.django_db
def test_qrcode_str(user):
    # Create a QRCode instance
    qr = QRCode.objects.create(
        user=user,
        qr_type="generic",
        content="Test content",
        cloudinary_url="http://example.com/qr.png",
        qr_image="http://example.com/qr.png"
    )
    expected = f"{user.username}'s generic QR"
    assert str(qr) == expected

@pytest.mark.django_db
def test_qrcode_clean(user):
    # Test that validation works when URL length exceeds limit.
    long_url = "http://" + "a" * 4100 + ".com"
    qr = QRCode(
        user=user,
        qr_type="generic",
        content="Test",
        cloudinary_url=long_url,
        qr_image=long_url
    )
    with pytest.raises(ValidationError):
        qr.clean()
