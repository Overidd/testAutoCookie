from django.urls import path
from .views import LoginUserView

urlpatterns = [
   path('login/', LoginUserView.as_view())
]