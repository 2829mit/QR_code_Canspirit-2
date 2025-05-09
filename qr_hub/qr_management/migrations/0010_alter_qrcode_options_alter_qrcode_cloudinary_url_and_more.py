# Generated by Django 5.1.5 on 2025-02-11 10:21

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('qr_management', '0009_qrlogo_qrpdf_qrsocialmedia_qrurl'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='qrcode',
            options={},
        ),
        migrations.AlterField(
            model_name='qrcode',
            name='cloudinary_url',
            field=models.URLField(blank=True, default='', max_length=500),
        ),
        migrations.AlterField(
            model_name='qrcode',
            name='content',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='qrcode',
            name='qr_image',
            field=models.URLField(max_length=500),
        ),
        migrations.AlterField(
            model_name='qrcode',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
