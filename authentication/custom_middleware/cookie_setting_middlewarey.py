from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
import logging

# Retrieve a logger named after the current module for structured logging.
logger = logging.getLogger(__name__)