# Generated by Django 5.1.4 on 2025-02-04 19:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('qr_management', '0007_alter_qrcode_options_remove_qrcode_cloudinary_url_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='qrcode',
            name='cloudinary_url',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
    ]
