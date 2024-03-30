from django.urls import path
from .views import (
    RegisterAPIView,
    LoginAPIView,
    UserAPIView,
    RefreshAPIView,
    LogoutAPIView,
    ForgotPasswordRequestView,
    ResetPasswordRequestView,
    TwoFactorAPIView, 
)

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("two-factor-login/", TwoFactorAPIView.as_view(), name="tow_factor_login"),
    path("user/", UserAPIView.as_view(), name="user"),
    path("token-refresh/", RefreshAPIView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordRequestView.as_view(), name="forgot_password"),
    path("reset-password/", ResetPasswordRequestView.as_view(), name="reset_password")
]
