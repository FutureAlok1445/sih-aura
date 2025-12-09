from django.urls import path
from . import views

urlpatterns = [
    path('scan/pcap/', views.upload_pcap, name='upload_pcap'),
    path("upload-capture/", views.upload_capture, name="upload_capture"),
    path("attacks/", views.attacks, name="attacks"),
    path("stats/", views.stats, name="stats"),
    path("traffic/", views.traffic, name="traffic"),
    path("explain/", views.analyze_attack, name="analyze_attack"),
 
]