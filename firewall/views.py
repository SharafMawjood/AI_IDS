from django.shortcuts import render, redirect
from .forms import FirewallRuleForm
from .models import FirewallRule


def firewall_rules(request):
    rules = FirewallRule.objects.all()
    return render(request, 'rules.html', {'rules': rules})


def add_rule(request):
    if request.method == 'POST':
        form = FirewallRuleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('firewall:rules')
    else:
        form = FirewallRuleForm()

    return render(request, 'firewall.html')
