import random
from faker import Faker
import qrcode
from io import BytesIO

from django.contrib.auth.models import User
from django.core.files.base import ContentFile

from .models import QRCode, Profile

# Initialize Faker instance
fake = Faker()

def generate_qr_code(content):
    """
    Generate a QR code image from the given content.
    
    Args:
        content (str): The text or URL to encode in the QR code.
        
    Returns:
        ContentFile: A Django-compatible image file of the QR code.
    """
    qr = qrcode.make(content)  # Create the QR code image
    img_io = BytesIO()  # Initialize an in-memory buffer
    qr.save(img_io, 'PNG')  # Save the image in PNG format to the buffer
    img_io.seek(0)  # Move the pointer to the beginning of the buffer

    # Return the buffer contents as a Django-compatible file
    return ContentFile(img_io.read(), name=f'qr_code_{random.randint(1000, 9999)}.png')


def populate_data(num_users=10, num_qrcodes=50):
    """
    Populate the database with fake users, profiles, and QR codes.
    
    Args:
        num_users (int): Number of users to create.
        num_qrcodes (int): Number of QR codes to create.
    """
    # Create fake users and their profiles
    for _ in range(num_users):
        username = fake.user_name()
        email = fake.email()
        password = "password123"  # Default password for all fake users
        
        # Ensure the username is unique before creating the user
        if not User.objects.filter(username=username).exists():
            user = User.objects.create_user(username=username, email=email, password=password)
            
            # Create a profile for the user with a random QR quota
            if not Profile.objects.filter(user=user).exists():
                Profile.objects.create(user=user, qr_quota=random.randint(5, 20))
    
    # Generate QR codes
    users = User.objects.all()
    for _ in range(num_qrcodes):
        user = random.choice(users)  # Randomly assign a user to each QR code
        profile = user.profile  # Access the user's profile
        
        # Skip QR code creation if the user's quota is exhausted
        if profile.qr_codes_created >= profile.qr_quota:
            print(f"User {user.username} has exhausted their quota.")
            continue
        
        content = fake.text(max_nb_chars=50)  # Generate random content for the QR code
        
        # Generate a QR code image
        qr_image = generate_qr_code(content)
        
        # Create a QRCode instance and associate it with the user
        QRCode.objects.create(user=user, content=content, image=qr_image, organization=user.organization)
        
        # Update the user's qr_codes_created count
        profile.qr_codes_created += 1
        profile.save()  # Save changes to the profile
        
        print(f"Generated QR code for user {user.username}. Total codes created: {profile.qr_codes_created}")
    
    print(f"Successfully populated {num_users} users and {num_qrcodes} QR codes.")
