# Generated by Django 5.1.5 on 2025-02-13 10:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('qr_management', '0017_alter_qrcode_qr_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='qrcode',
            name='qr_image',
            field=models.URLField(blank=True, max_length=4096, null=True),
        ),
    ]
