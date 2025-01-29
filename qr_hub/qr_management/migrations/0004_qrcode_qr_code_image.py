# Generated by Django 5.1.5 on 2025-01-29 06:21

import cloudinary.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('qr_management', '0003_qrcode_content'),
    ]

    operations = [
        migrations.AddField(
            model_name='qrcode',
            name='qr_code_image',
            field=cloudinary.models.CloudinaryField(blank=True, max_length=255, null=True, verbose_name='image'),
        ),
    ]
