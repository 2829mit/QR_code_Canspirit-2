# conftest.py
import pytest
from django.contrib.auth import get_user_model
from qr_management.models import Organization

User = get_user_model()

@pytest.fixture
def organization(db):
    return Organization.objects.create(name="Test Organization", address="123 Test St.")

@pytest.fixture
def user(db, organization):
    # Create a test user with an organization and default QR quota settings
    user = User.objects.create_user(
        username="testuser",
        password="password123",
        organization=organization,
        qr_quota=10,
        qr_codes_created=0
    )
    return user
