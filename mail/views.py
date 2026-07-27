import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SendEmailAPIView(APIView):
    """
    Contact-form endpoint. Always delivers to DEFAULT_FROM_EMAIL (the site
    owner's own inbox) -- the recipient is never client-controlled. An
    endpoint that lets an anonymous caller pick an arbitrary "to" address
    while sending through our own mailbox is an open spam relay, not a
    contact form, so the visitor's email is only ever used as the Reply-To
    header.
    """

    permission_classes = [AllowAny]
    throttle_scope = "contact"

    def post(self, request, *args, **kwargs):
        """
        Handle POST request to send a contact-form email.

        Expected request data:
        {
            "reply_to": "visitor_email@example.com",
            "subject": "Email subject",
            "content": "Plain text content of the email"
        }

        Returns:
            Response: JSON response indicating success or failure of email sending.
        """
        data = request.data
        reply_to = data.get("reply_to", "").strip()
        subject = data.get("subject", "").strip()
        content = data.get("content", "").strip()

        if not reply_to or not subject or not content:
            return Response(
                {"error": "reply_to, subject, and content are all required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_email(reply_to)
        except ValidationError:
            return Response({"error": "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            message = EmailMultiAlternatives(
                subject=f"[Contact form] {subject}",
                body=content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[settings.DEFAULT_FROM_EMAIL],
                reply_to=[reply_to],
            )
            message.send()

            logger.info("Contact form email sent, reply-to %s", reply_to)
            return Response({"message": "Email sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            # Log the detailed error
            logger.error("Error sending contact form email", exc_info=True)

            # Return error response
            return Response({"error": "Error sending email: " + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
