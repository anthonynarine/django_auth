from django.urls import path
from .views import (
    RegisterAPIView,
    LoginAPIView,
    UserAPIView,
    RefreshAPIView,
    LogoutAPIView,
    ForgotPasswordRequestView,
    ResetPasswordRequestView,
    TwoFactorLoginAPIView, 
    GenerateQRCodeAPIView,
    Verify2FASetupAPIView,
)

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("two-factor-login/", TwoFactorLoginAPIView.as_view(), name="tow_factor_login"),
    path("token-refresh/", RefreshAPIView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordRequestView.as_view(), name="forgot_password"),
    path("reset-password/", ResetPasswordRequestView.as_view(), name="reset_password"),
    path("generate-qr/", GenerateQRCodeAPIView.as_view(), name="generate_qr_code"),
    path("verify-otp/", Verify2FASetupAPIView.as_view(), name="verify_2fa_setup"),
    path("user/", UserAPIView.as_view(), name="fetch_user"),
]
