from django.apps import AppConfig


class QrManagementConfig(AppConfig):
    """
    Configuration class for the 'qr_management' application.
    This class handles app-specific settings and initialization logic.
    """
    default_auto_field = 'django.db.models.BigAutoField'  # Default field type for auto-generated primary keys
    name = 'qr_management'  # Name of the application

