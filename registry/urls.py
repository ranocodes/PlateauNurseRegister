from django.urls import path

from . import views

app_name = "registry"

urlpatterns = [
    


path("", views.home, name="home"),
    path("hr/register/", views.hr_registration, name="hr_registration"),
    path("register/", views.register, name="register"),
    path(
        "register/success/<int:pk>/",
        views.registration_success,
        name="registration_success",
    ),
    path("documents/<int:pk>/", views.protected_document, name="protected_document"),
    path(
        "nurses/<int:pk>/photo/",
        views.protected_nurse_photo,
        name="protected_nurse_photo",
    ),
    path("verify/", views.verify, name="verify"),
    path("verify/<str:nanm_id>/", views.verify_result, name="verify_result"),
    path("verify/<str:nanm_id>/photo/", views.public_nurse_photo, name="public_nurse_photo"),
    path("verify/<str:nanm_id>/qr/", views.nurse_qr, name="nurse_qr"),
    path("nurses/<int:pk>/card/", views.card, name="card"),
    path("nurses/<int:pk>/approval/", views.approval_confirmation, name="approval_confirmation"),
    path("nurses/<int:pk>/email-card/", views.email_card_link, name="email_card_link"),
    path("card/<str:token>/", views.signed_card, name="signed_card"),
    path("hr/review/<int:pk>/", views.approve_hr_registration, name="approve_hr_registration"),
]
