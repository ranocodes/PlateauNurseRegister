import mimetypes
from io import BytesIO
from pathlib import Path

import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django_ratelimit.decorators import ratelimit

from .forms import HRRegistrationForm, NurseRegistrationForm
from .models import Employer, HRRegistrationRequest, LicenceDocument, Nurse
from .permissions import (
    HR,
    can_view_documents,
    can_view_nurse_photo,
    is_hr,
    is_staff_reviewer,
    is_super_admin,
)

User = get_user_model()


def public_verify_rate(request, group=None):
    return settings.PUBLIC_VERIFY_RATE


def ratelimited(request, exception=None):
    return HttpResponse("Too many requests. Try again later.", status=429)


def home(request):
    return render(request, "home.html")


def register(request):
    if request.method == "POST":
        form = NurseRegistrationForm(
            request.POST,
            request.FILES,
            user=request.user if request.user.is_authenticated else None,
        )
        if form.is_valid():
            with transaction.atomic():
                nurse = form.save()
                LicenceDocument.objects.create(
                    nurse=nurse,
                    file=form.cleaned_data["licence_scan"],
                    document_type=LicenceDocument.DocumentType.INITIAL,
                )
            return redirect("registry:registration_success", pk=nurse.pk)
    else:
        form = NurseRegistrationForm(user=request.user if request.user.is_authenticated else None)

    return render(request, "register.html", {"form": form})


def registration_success(request, pk):
    nurse = get_object_or_404(Nurse, pk=pk)
    return render(request, "registration_success.html", {"nurse": nurse})


@login_required
def protected_document(request, pk):
    if not can_view_documents(request.user):
        raise PermissionDenied

    document = get_object_or_404(
        LicenceDocument.objects.select_related("nurse__employer"),
        pk=pk,
    )
    return _serve_media(document.file)


@login_required
def protected_nurse_photo(request, pk):
    nurse = get_object_or_404(Nurse.objects.select_related("employer"), pk=pk)
    if not can_view_nurse_photo(request.user, nurse):
        raise PermissionDenied

    return _serve_media(nurse.photo)


def _serve_media(field_file):
    if not field_file:
        raise Http404

    try:
        path = Path(field_file.path).resolve()
    except (NotImplementedError, ValueError) as exc:
        raise Http404 from exc

    media_root = Path(settings.MEDIA_ROOT).resolve()
    if not path.is_relative_to(media_root) or not path.is_file():
        raise Http404

    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return FileResponse(path.open("rb"), content_type=content_type)


@csrf_exempt
@ratelimit(key="ip", rate=public_verify_rate, method=["GET", "POST"], block=True)
def verify(request):
    """Public verification page."""
    if request.method == "POST":
        website = request.POST.get("website", "").strip()
        if website:
            return HttpResponseBadRequest("Bad request")

    nanm_id = (request.GET.get("nanm_id") or request.POST.get("nanm_id") or "").strip()
    if not nanm_id:
        return render(request, "verify.html")
    nurse = Nurse.objects.select_related("employer").filter(nanm_id=nanm_id).first()
    if not nurse:
        return render(request, "verify.html", {"not_registered": True})

    if is_hr(request.user) and request.user.is_authenticated:
        return render(
            request,
            "verify.html",
            {
                "nurse": nurse,
                "status": nurse.public_licence_status,
                "nanm_id": nurse.nanm_id,
                "full_name": nurse.full_name,
                "licence_expiry": nurse.licence_expiry,
                "employer": nurse.employer.name if nurse.employer else "",
                "photo_url": request.build_absolute_uri(nurse.photo.url) if nurse.photo else "",
            },
        )

    if not request.user.is_authenticated and not nurse:
        return render(request, "verify.html", {"not_registered": True})

    return render(
        request,
        "verify.html",
        {
            "nurse": nurse,
            "status": nurse.public_licence_status,
            "nanm_id": nurse.nanm_id,
            "full_name": nurse.full_name,
            "licence_expiry": nurse.licence_expiry,
            "employer": nurse.employer.name if nurse.employer else "",
            "photo_url": request.build_absolute_uri(nurse.photo.url) if nurse.photo else "",
        },
    )


@ratelimit(key="ip", rate=public_verify_rate, method=["GET", "POST"], block=True)
def verify_result(request, nanm_id):
    """Show verification result for a given NANNM ID."""
    nurse = Nurse.objects.select_related("employer").filter(nanm_id=nanm_id).first()
    if not nurse:
        return render(request, "verify.html", {"not_registered": True})

    return render(
        request,
        "verify.html",
        {
            "nurse": nurse,
            "status": nurse.public_licence_status,
            "nanm_id": nurse.nanm_id,
            "full_name": nurse.full_name,
            "licence_expiry": nurse.licence_expiry,
            "employer": nurse.employer.name if nurse.employer else "",
            "photo_url": request.build_absolute_uri(nurse.photo.url) if nurse.photo else "",
        },
    )


@ratelimit(key="ip", rate=public_verify_rate, method=["GET", "POST"], block=True)
def public_nurse_photo(request, nanm_id):
    nurse = Nurse.objects.filter(nanm_id=nanm_id).first()
    if not nurse or not nurse.photo:
        raise Http404
    return _serve_media(nurse.photo)


@ratelimit(key="ip", rate=public_verify_rate, method=["GET", "POST"], block=True)
def nurse_qr(request, nanm_id):
    nurse = Nurse.objects.filter(nanm_id=nanm_id).first()
    if not nurse or not nurse.nanm_id:
        raise Http404

    qr_url = f"{settings.PUBLIC_BASE_URL.rstrip('/')}/verify/{nurse.nanm_id}/"
    image = qrcode.make(qr_url)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    response = HttpResponse(buffer.getvalue(), content_type="image/png")
    response["Cache-Control"] = "no-store"
    return response


@login_required
def approval_confirmation(request, pk):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied

    nurse = get_object_or_404(Nurse, pk=pk)
    if nurse.record_status != Nurse.RecordStatus.APPROVED or not nurse.nanm_id:
        raise Http404

    direct_url = request.build_absolute_uri(reverse("registry:card", args=[nurse.pk]))
    signed_url = request.build_absolute_uri(
        reverse("registry:signed_card", args=[signing.dumps({"nurse_id": nurse.pk}, salt=settings.CARD_LINK_SALT)])
    )
    return render(
        request,
        "approval_confirmation.html",
        {
            "nurse": nurse,
            "direct_url": direct_url,
            "signed_url": signed_url,
        },
    )


@login_required
@csrf_exempt
def email_card_link(request, pk):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    nurse = get_object_or_404(Nurse, pk=pk)
    if nurse.record_status != Nurse.RecordStatus.APPROVED or not nurse.nanm_id:
        raise Http404

    token = signing.dumps({"nurse_id": nurse.pk}, salt=settings.CARD_LINK_SALT)
    signed_url = request.build_absolute_uri(reverse("registry:signed_card", args=[token]))
    send_mail = __import__("django.core.mail", fromlist=["send_mail"]).send_mail
    send_mail(
        "Nurse card link",
        f"Open the following card link: {signed_url}",
        settings.DEFAULT_FROM_EMAIL,
        [nurse.email],
        fail_silently=True,
    )
    return redirect("registry:approval_confirmation", pk=nurse.pk)


@login_required
def card(request, pk):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied

    nurse = get_object_or_404(Nurse.objects.select_related("employer"), pk=pk)
    token = signing.dumps({"nurse_id": nurse.pk}, salt=settings.CARD_LINK_SALT)
    signed_url = request.build_absolute_uri(reverse("registry:signed_card", args=[token]))
    direct_url = reverse("registry:card", args=[pk])
    ctx = {
        "nurse": nurse,
        "signed": False,
        "signed_url": signed_url,
        "direct_url": direct_url,
        "qr_url": request.build_absolute_uri(reverse("registry:nurse_qr", args=[nurse.nanm_id])) if nurse.nanm_id else "",
    }
    return render(request, "card.html", ctx)


def signed_card(request, token):
    try:
        data = signing.loads(
            token,
            salt=settings.CARD_LINK_SALT,
            max_age=settings.CARD_LINK_MAX_AGE,
        )
        nurse = get_object_or_404(Nurse.objects.select_related("employer"), pk=data["nurse_id"])
        return render(
            request,
            "card.html",
            {
                "nurse": nurse,
                "signed": True,
                "signed_url": request.build_absolute_uri(reverse("registry:signed_card", args=[token])),
                "direct_url": request.build_absolute_uri(reverse("registry:card", args=[nurse.pk])),
                "qr_url": request.build_absolute_uri(reverse("registry:nurse_qr", args=[nurse.nanm_id])) if nurse.nanm_id else "",
            },
        )
    except Exception:
        return render(request, "card_invalid.html", status=400)


def hr_registration(request):
    if request.user.is_authenticated:
        if not is_super_admin(request.user):
            return redirect("admin:index")
    if request.method == "POST":
        form = HRRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your HR registration has been submitted for super-admin review.")
            return redirect("registry:home")
    else:
        form = HRRegistrationForm()
    return render(request, "hr_registration.html", {"form": form})


@login_required
def approve_hr_registration(request, pk):
    if not is_super_admin(request.user):
        raise PermissionDenied

    registration = get_object_or_404(HRRegistrationRequest, pk=pk)
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "approve":
            with transaction.atomic():
                employer, _ = Employer.objects.get_or_create(
                    name=registration.hospital_name,
                    defaults={
                        "type": registration.employer_type,
                        "lga": registration.lga,
                        "contact_email": registration.contact_email,
                        "approved": True,
                    },
                )
                username = registration.email.split("@", 1)[0]
                if User.objects.filter(email__iexact=registration.email).exists():
                    raise ValidationError("An account already exists for this email.")
                if User.objects.filter(username__iexact=username).exists():
                    username = registration.email
                if User.objects.filter(username__iexact=username).exists():
                    raise ValidationError("Could not allocate a unique username for this account.")
                user = User.objects.create_user(username=username, email=registration.email)
                user.email = registration.email
                user.password = registration.password
                user.is_staff = True
                user.save()
                user.groups.add(Group.objects.get(name=HR))
                employer.hr_users.add(user)
                registration.status = HRRegistrationRequest.Status.APPROVED
                registration.reviewed_by = request.user
                registration.reviewed_at = timezone.now()
                registration.save(update_fields=["status", "reviewed_by", "reviewed_at", "updated_at"])
            messages.success(request, f"HR account for {registration.email} approved and activated.")
            return redirect("admin:registry_hrregistrationrequest_changelist")
        if action == "reject":
            reason = (request.POST.get("reason") or "").strip()
            registration.status = HRRegistrationRequest.Status.REJECTED
            registration.reviewed_by = request.user
            registration.reviewed_at = timezone.now()
            registration.reason = reason or "No reason provided"
            registration.save(update_fields=["status", "reviewed_by", "reviewed_at", "reason", "updated_at"])
            messages.success(request, f"HR registration for {registration.email} rejected.")
            return redirect("admin:registry_hrregistrationrequest_changelist")
    return render(request, "admin_hr_registration_review.html", {"registration": registration})




