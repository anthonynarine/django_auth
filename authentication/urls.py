
from os import name
from turtle import home
from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("user.urls")),
    
]
