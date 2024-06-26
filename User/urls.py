from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout' ),
    path('check/', views.check_user_exists, name='check'),
    path('check/email/', views.check_user_email, name='check_email'),
    path("check/<str:email>/user", views.check_user_data_email, name="check_email")
]