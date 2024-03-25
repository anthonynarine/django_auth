from decouple import config
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from rest_framework import status

class SendEmailAPIView(APIView):
    def post(self, request, *args, **kwargs):
        email_data = request.data
        email_message = Mail(
            from_email=email_data.get("from_email"),
            to_emails=email_data.get("to_email"),
            subject=email_data.get("subject"),
            html_content=email_data.get("content"),
        )
        try:
            sg = SendGridAPIClient(config("SENDGRID_API_KEY"))
            sg_response = sg.send(email_message)
            print("SendGrid response status:", sg_response.status_code)  # Debugging
            print("SendGrid response body:", sg_response.body)  # Debugging
            return Response({"message": "Email sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            print("Error sending email:", e)
            return Response({"error": "Error sending email: " + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
