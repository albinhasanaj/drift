# Django views using the models
from django.http import JsonResponse
from .models import User, Post

def get_user(request, user_id):
    user = User.objects.get(id=user_id)
    return JsonResponse({'name': user.name, 'email': user.email})

def create_user(request):
    user = User.objects.create(
        email=request.POST['email'],
        password=request.POST['password'],
        name=request.POST['name'],
    )
    return JsonResponse({'id': user.id})
