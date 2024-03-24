import stat
from urllib import response
from decouple import config
from email import message
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from rest_framework import status

class SendEmailAPIView(APIView):
    def post(self, request, *args, **kwargs):
        email_data = request.data
        message = Mail(
            from_email=email_data.get("from_email"),
            to_emails=email_data.get("to_email"),
            subject=email_data.get("subject"),
            html_content=email_data.get("content"),
        )
        try:
            sg = SendGridAPIClient(config("SENDGRID_API_KEY"))
            response = sg.send(message)
            return Response({"message": "Email sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
