from django.urls import path
from . import views

urlpatterns = [
    path("rules/", views.firewall_rules),
    path("add_rule/", views.add_rule)
]
