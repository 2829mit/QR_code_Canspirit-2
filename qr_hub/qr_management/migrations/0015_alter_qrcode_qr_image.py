# Generated by Django 5.1.5 on 2025-02-13 10:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('qr_management', '0014_qrcode_logo'),
    ]

    operations = [
        migrations.AlterField(
            model_name='qrcode',
            name='qr_image',
            field=models.TextField(blank=True, null=True),
        ),
    ]
