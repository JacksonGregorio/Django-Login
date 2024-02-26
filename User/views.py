from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
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
        response['Authorization'] = f'Bearer {str(refresh.access_token)}' #respota do token pelo header
        return response
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

@csrf_exempt
def logout(request):
    if request.method == "POST":
        response = HttpResponse(status=200)
        response['Authorization'] = ''
        return response
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def check_user_exists(request):
    if request.method == "GET":
        token = request.META.get('HTTP_AUTHORIZATION', "Bearer ").split(' ')[1]
        print(token)
        try:
            UntypedToken(token)
        except (InvalidToken, TokenError) as e:
            return JsonResponse({'error': 'Invalid token', 'detail': str(e)}, status=400)
        user = JWTAuthentication().get_user(UntypedToken(token))
        if user is not None:
            return JsonResponse({'exists': True}, status=200)
        else:
            return JsonResponse({'exists': False}, status=404)
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def check_user_email(request):
    if request.method == "GET":
        token = request.META.get('HTTP_AUTHORIZATION', "Bearer ").split(' ')[1]
        print(token)
        try:
            UntypedToken(token)
        except (InvalidToken, TokenError) as e:
            return JsonResponse({'error': 'Invalid token', 'detail': str(e)}, status=400)
        user = JWTAuthentication().get_user(UntypedToken(token))
        if user is not None:
            user = get_object_or_404(AbstractUser, email=user.email)
            return JsonResponse({"email" : user.email}, status=200)
        else:
            return JsonResponse({'exists': False}, status=404)
    return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def check_user_data_email(request, email):
    emaildata = email
    if request.method == "GET":
        token = request.META.get('HTTP_AUTHORIZATION', "Bearer ").split(' ')[1]
        print(token)
        try:
            UntypedToken(token)
        except (InvalidToken, TokenError) as e:
            return JsonResponse({'error': 'Invalid token', 'detail': str(e)}, status=400)
        user = JWTAuthentication().get_user(UntypedToken(token))
        if user is not None:
            user = get_object_or_404(AbstractUser, email=user.email, id=user.id)
            if user.email == emaildata:  # Checa se o email do token é igual ao email do parametro
                return JsonResponse({"email" : user.email, "id" : user.id}, status=200)
            else:
                return JsonResponse({'error': 'This use email is not compatibility'}, status=404)
        else:
            return JsonResponse({'exists': False}, status=404)