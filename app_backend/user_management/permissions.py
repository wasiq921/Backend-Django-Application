

from rest_framework import permissions

class AdminOnly(permissions.BasePermission):
    """
    Allows access only to admin users.
    Allows admin to post and get to other users
    """
    message = 'Only admin users are allowed to perform this action. '

    def has_permission(self, request, view):
        if not request.user.is_authenticated or not hasattr(request.user, 'profile'):
            return False
        elif request.user.profile.role == 'admin':
            return True
        else:
            return False

class AdminOrReadOnly(permissions.IsAdminUser):
    """
    Allows access only to admin users.
    Allows admin to post and get to other users
    """
    message = 'Only admin users are allowed to perform this action.'

    def has_permission(self, request, view):
        if not request.user.is_authenticated or not hasattr(request.user, 'profile'):
            return request.method in permissions.SAFE_METHODS
        else:
            return super().has_permission(request, view)


class IsAdminOnly(permissions.BasePermission):
    message = 'Only admins can perform this action'

    def has_permission(self, request, view):
        if request.user.is_authenticated and hasattr(request.user, 'profile') and request.user.profile.role == 'admin':
            return True
        else:
            return False
