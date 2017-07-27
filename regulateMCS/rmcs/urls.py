from django.conf.urls import url

from . import views

# configure urls here
urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^handlePR/', views.github_webhook_handler, name='github_webhook_handler')
]