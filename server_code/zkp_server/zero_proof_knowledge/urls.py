from django.urls import path
from .views import validate_zero_proof_knowledge

urlpatterns = [
    path('zero_proof_knowledge/', validate_zero_proof_knowledge, name='validate-zpk')
]
