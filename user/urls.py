from django.urls import path
from .views import (
    RegisterAPIView,
    LoginAPIView,
    UserAPIView,
    RefreshAPIView,
    LogoutAPIView,
    ForgotPasswordRequestView,
    ResetPasswordRequestView,
)


urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("user/", UserAPIView.as_view(), name="user"),
    path("refresh/", RefreshAPIView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordRequestView.as_view(), name="reset_password"),
    path("reset-password/", ResetPasswordRequestView.as_view(), name="reset_password")
]
