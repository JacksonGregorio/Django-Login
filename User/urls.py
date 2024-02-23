from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('login/', views.login),
]