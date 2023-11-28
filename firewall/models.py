from django.db import models


class FirewallRule(models.Model):
    name = models.CharField(max_length=255)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10)
    action = models.CharField(max_length=10, choices=[
                              ('allow', 'Allow'), ('deny', 'Deny')])

    def __str__(self):
        return self.name
