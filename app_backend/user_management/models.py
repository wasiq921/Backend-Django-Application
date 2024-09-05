from django.db import models
from django.contrib.auth.models import User
from datetime import datetime ,date

# Create your models here.


class Role(models.Model):
    name = models.CharField(max_length=50)
    display_name = models.CharField(max_length=50, default="")
    created_on = models.DateTimeField(auto_now_add=True)
    active=models.BooleanField(default=True)

    @classmethod
    def get_default_role(cls):
        obj, _ = cls.objects.get_or_create(
            name="user",
            defaults={
                    "name": "user",
                    "display_name": "User",
                    "active": True
            }
        )
        return obj.pk

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'role'

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name = "profile")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="user_role", default=Role.get_default_role)
    join_date = models.DateField(default=date.today)
    is_delete = models.BooleanField(default=False)
    country = models.CharField(blank=True , null = True)
    city = models.CharField(blank=True , null = True)
    date_of_birth = models.DateField(null=True, blank=True)
    about = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default = True)
    
    def __str__(self):
        return '%s' % self.user.email
    
    def get_full_name(self):
        return self.user.first_name+" "+self.user.last_name
    
    class Meta:
        db_table = 'profile'

class App(models.Model):
    i_profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    name = models.CharField(max_length=256)
    description = models.TextField()

    def __str__(self) -> str:
        return '%s - %s' % (self.name, self.i_profile.get_full_name())
    
    class Meta:
        db_table = 'app'