# Generated by Django 5.1.4 on 2025-01-30 10:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('qr_management', '0004_qrcode_qr_code_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='qrcode',
            name='cloudinary_url',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
    ]
