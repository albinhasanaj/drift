# Django models with sensitive fields
from django.db import models

class User(models.Model):
    email = models.EmailField(unique=True)  # SENSITIVE
    password = models.CharField(max_length=128)  # SENSITIVE
    ssn = models.CharField(max_length=11, blank=True)  # SENSITIVE
    name = models.CharField(max_length=100)
    role = models.CharField(max_length=20, default='user')

    class Meta:
        db_table = 'users'

class Post(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
