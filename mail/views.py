import logging
from decouple import config
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from rest_framework import status


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SendEmailAPIView(APIView):
    """
    API view to handle sending emails using SendGrid.
    """
    def post(self, request, *args, **kwargs):
        """
        Handle POST request to send email.
        
        Expected request data:
        {
            "from_email": "sender_email@example.com",
            "to_email": "recipient_email@example.com,
            "subject": "Email subject",
            "content": "HTML content fo the email"
        }
        
        Returns:
            Response: JSON reqponse indicating success or failure of email sending
        """
        email_data = request.data
        
        # Create the email message
        email_message = Mail(
            from_email=email_data.get("from_email"),
            to_emails=email_data.get("to_email"),
            subject=email_data.get("subject"),
            html_content=email_data.get("content"),
        )
        try:
            # Send the email useing SendGrid
            sg = SendGridAPIClient(config("SENDGRID_API_KEY"))
            sg_response = sg.send(email_message)
            
                        # Log the SendGrid response
            logger.info("SendGrid response status: %s", sg_response.status_code)
            logger.info("SendGrid response body: %s", sg_response.body)
            
            # Return success response
            return Response({"message": "Email sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            # Log the error
            logger.error("Error sending email: %s", str(e))
            
            return Response({"error": "Error sending email: " + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
