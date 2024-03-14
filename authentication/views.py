from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render


# def home(request):
#     return HttpResponse("SURPRISE MOTHER FUCKER")

# def home(request):
#     return HttpResponseRedirect('https://documenter.getpostman.com/view/23868442/2sA2xh3tTu')


def home(request):
    return render(request, "home.html")


