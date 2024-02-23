from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, HttpResponse
from .models import AbstractUser
import json

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_list(request):
    if request.method == "GET":
        users = list(AbstractUser.objects.values())  
        return JsonResponse(users, safe=False)
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def user_create(request):
    if request.method == "POST":
        data = json.loads(request.body)
        data['password'] = make_password(data['password'])
        user = AbstractUser.objects.create(**data)
        return JsonResponse({'id': user.pk}, status=201)
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

@csrf_exempt
def login(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        User = AbstractUser
        try:
            user = User.objects.get(email=email)
            if not user.check_password(password):
                raise User.DoesNotExist
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)
        refresh = RefreshToken.for_user(user)
        response = HttpResponse(status=200)
        response['Authorization'] = f'Bearer {str(refresh.access_token)}'
        return response
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)
