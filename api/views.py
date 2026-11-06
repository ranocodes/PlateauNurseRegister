from django.contrib.auth import authenticate, get_user_model, update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
import smtplib
from django.conf import settings
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.http import FileResponse
from django_ratelimit.decorators import ratelimit
from django.contrib.auth.models import Group
from django.db import transaction
from django.core import signing
from django.core.exceptions import ValidationError as DjangoValidationError
from django.urls import reverse
from django.utils.dateparse import parse_date
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from registry.forms import HRRegistrationForm, NurseRegistrationForm
from registry.models import Employer, HRRegistrationRequest, LicenceDocument, Nurse
from registry.permissions import HR, SUPER_ADMIN, SUPERVISOR, is_hr, is_staff_reviewer, is_super_admin, nurses_for_user
from registry.services import transition_nurse
from .serializers import NurseProfileSerializer, PublicNurseSerializer


@api_view(["GET"])
@permission_classes([AllowAny])
def verify_nurse(request, nanm_id):
    try:
        nurse = Nurse.objects.select_related("employer").get(nanm_id=nanm_id)
    except Nurse.DoesNotExist as exc:
        raise NotFound({"detail": "Not registered"}) from exc
    serializer = PublicNurseSerializer(nurse, context={"request": request})
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([AllowAny])
def verify_nurse_photo(request, nanm_id):
    nurse = Nurse.objects.filter(nanm_id=nanm_id).first()
    if not nurse or not nurse.photo:
        raise NotFound("Registry photo not found.")
    try:
        photo = nurse.photo.open("rb")
    except (OSError, ValueError) as exc:
        raise NotFound("Registry photo is unavailable.") from exc
    from mimetypes import guess_type
    response = FileResponse(photo, content_type=guess_type(nurse.photo.name)[0] or "application/octet-stream")
    response["Cache-Control"] = "public, max-age=300"
    response["X-Content-Type-Options"] = "nosniff"
    return response


User = get_user_model()


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def token_logout(request):
    if request.auth is not None and hasattr(request.auth, "delete"):
        request.auth.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    current = request.data.get("current_password") or ""
    new_password = request.data.get("new_password") or ""
    if not request.user.check_password(current):
        raise ValidationError({"current_password": "Current password is incorrect."})
    try:
        validate_password(new_password, request.user)
    except DjangoValidationError as exc:
        raise ValidationError({"new_password": list(exc.messages)}) from exc
    request.user.set_password(new_password)
    request.user.save(update_fields=["password"])
    update_session_auth_hash(request, request.user)
    return Response({"detail": "Password updated."})


@api_view(["POST"])
@permission_classes([AllowAny])
@ratelimit(key="ip", rate="5/h", method="POST", block=True)
def request_password_reset(request):
    email = (request.data.get("email") or "").strip()
    user = User.objects.filter(email__iexact=email, is_active=True).first() if email else None
    if user and user.has_usable_password():
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = f"{settings.FRONTEND_BASE_URL}/reset-password/{uid}/{token}"
        message = (
            f"A password reset was requested for your Plateau State Nurse Registry account.\n\n"
            f"Choose a new password using this one-time link:\n{reset_url}\n\n"
            "If you did not request this, you can ignore this email. The link expires automatically."
        )
        try:
            send_mail(
                subject="Reset your Nurse Registry password",
                message=message,
                from_email=None,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Password reset email delivery failed")
            detail = "Password reset email could not be sent. Please check the mail server configuration and try again."
            if isinstance(exc, smtplib.SMTPAuthenticationError):
                detail = "Gmail rejected the SMTP sign-in. Check the Gmail address and Google App Password in .env."
            elif isinstance(exc, smtplib.SMTPRecipientsRefused):
                detail = "The email provider rejected this recipient address. Check the email saved on the account."
            elif isinstance(exc, smtplib.SMTPDataError):
                detail = f"Gmail rejected the email message (SMTP {exc.smtp_code}). Check the sender address and Gmail limits."
            elif settings.DEBUG and not (settings.EMAIL_HOST_USER and settings.EMAIL_HOST_PASSWORD):
                detail = (
                    "Gmail delivery needs EMAIL_HOST_USER set to the Gmail address and EMAIL_HOST_PASSWORD set to a "
                    "Google App Password in .env. Restart Django after saving the values."
                )
            elif settings.DEBUG:
                detail = f"Email delivery failed ({type(exc).__name__}). See the Django server log for the SMTP detail."
            return Response(
                {"detail": detail},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
    response_data = {"detail": "If an active account uses that email, a password reset link has been sent."}
    if settings.DEBUG and settings.EMAIL_BACKEND.endswith("console.EmailBackend"):
        response_data["delivery_hint"] = "Development email is printed in the Django server terminal."
    return Response(response_data)


@api_view(["POST"])
@permission_classes([AllowAny])
@ratelimit(key="ip", rate="10/h", method="POST", block=True)
def confirm_password_reset(request, uidb64, token):
    try:
        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=user_id, is_active=True)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        raise ValidationError({"token": "This password reset link is invalid or expired."})
    if not default_token_generator.check_token(user, token):
        raise ValidationError({"token": "This password reset link is invalid or expired."})
    new_password = request.data.get("new_password") or ""
    try:
        validate_password(new_password, user)
    except DjangoValidationError as exc:
        raise ValidationError({"new_password": list(exc.messages)}) from exc
    user.set_password(new_password)
    user.save(update_fields=["password"])
    Token.objects.filter(user=user).delete()
    return Response({"detail": "Password updated. Sign in with your new password."})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_document_content(request, pk):
    from registry.permissions import can_view_documents
    if not can_view_documents(request.user):
        raise PermissionDenied("You cannot view private registry documents.")
    document = LicenceDocument.objects.select_related("nurse").filter(pk=pk).first()
    if not document:
        raise NotFound("Document not found.")
    from mimetypes import guess_type
    try:
        file_handle = document.file.open("rb")
    except (OSError, ValueError) as exc:
        raise NotFound("Document is unavailable.") from exc
    response = FileResponse(file_handle, content_type=guess_type(document.file.name)[0] or "application/octet-stream")
    response["Content-Disposition"] = "inline"
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "private, no-store"
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
@ratelimit(key="ip", rate="10/m", method="POST", block=True)
def token_login(request):
    identifier = (
        request.data.get("identifier")
        or request.data.get("email")
        or request.data.get("username")
        or ""
    ).strip()
    password = request.data.get("password") or ""
    user_record = User.objects.filter(email__iexact=identifier).first()
    if user_record is None:
        user_record = User.objects.filter(username__iexact=identifier).first()
    user = authenticate(request, username=user_record.get_username(), password=password) if user_record else None
    if not user:
        return Response({"detail": "Invalid email or password."}, status=status.HTTP_400_BAD_REQUEST)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({"token": token.key, "access": token.key})


@api_view(["POST"])
@permission_classes([AllowAny])
def register_nurse(request):
    email = (request.data.get("email") or "").strip().lower()
    password = request.data.get("password") or ""
    if not password or len(password) < 8:
        raise ValidationError({"password": "Use a password with at least 8 characters."})
    if User.objects.filter(email__iexact=email).exists() or User.objects.filter(username__iexact=email).exists():
        raise ValidationError({"email": "An account already exists for this email."})
    form = NurseRegistrationForm(request.data, request.FILES)
    if not form.is_valid():
        raise ValidationError(form.errors)
    with transaction.atomic():
        user = User.objects.create_user(username=email, email=email, password=password)
        nurse = form.save(commit=False)
        nurse.user = user
        nurse.save()
        LicenceDocument.objects.create(
            nurse=nurse,
            file=form.cleaned_data["licence_scan"],
            document_type=LicenceDocument.DocumentType.INITIAL,
        )
        token = Token.objects.create(user=user)
    return Response(
        {"token": token.key, "access": token.key, "nurse": NurseProfileSerializer(nurse, context={"request": request}).data},
        status=status.HTTP_201_CREATED,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def current_user(request):
    user = request.user
    nurse = getattr(user, "nurse_profile", None)
    employers = list(user.employers.values("id", "name", "type", "lga", "contact_email", "approved")) if is_hr(user) else []
    return Response({
        "id": user.pk,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": "hr" if is_hr(user) else ("super_admin" if is_super_admin(user) else "supervisor" if user.groups.filter(name=SUPERVISOR).exists() else "reviewer" if is_staff_reviewer(user) else "nurse" if nurse else "user"),
        "nurse": NurseProfileSerializer(nurse, context={"request": request}).data if nurse else None,
        "employers": employers,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def nurse_profile(request):
    nurse = getattr(request.user, "nurse_profile", None)
    if not nurse:
        raise PermissionDenied("This account has no nurse profile.")
    return Response(NurseProfileSerializer(nurse, context={"request": request}).data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def hr_nurses(request):
    if not (is_hr(request.user) or is_staff_reviewer(request.user)):
        raise PermissionDenied
    nurses = nurses_for_user(request.user).select_related("employer")
    return Response(NurseProfileSerializer(nurses, many=True, context={"request": request}).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def confirm_employment(request, pk):
    if not is_hr(request.user):
        raise PermissionDenied

    with transaction.atomic():
        nurse = nurses_for_user(request.user).select_for_update().filter(pk=pk).first()

        if not nurse:
            raise NotFound("Nurse not found for your employer.")

        if nurse.employment_status != Nurse.EmploymentStatus.PENDING:
            raise ValidationError("This employment record has already been decided.")

        decided_at = timezone.now()

        nurse.employment_status = Nurse.EmploymentStatus.CONFIRMED
        nurse.employment_decided_at = decided_at
        nurse.employment_decided_by = request.user
        nurse.employer_confirmed_at = decided_at
        nurse.employer_confirmed_by = request.user

        nurse.save(update_fields=[
            "employment_status",
            "employment_decided_at",
            "employment_decided_by",
            "employer_confirmed_at",
            "employer_confirmed_by",
            "updated_at",
        ])

    return Response(NurseProfileSerializer(nurse, context={"request": request}).data)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def reject_employment(request, pk):
    if not is_hr(request.user):
        raise PermissionDenied

    with transaction.atomic():
        nurse = nurses_for_user(request.user).select_for_update().filter(pk=pk).first()

        if not nurse:
            raise NotFound("Nurse not found for your employer.")

        if nurse.employment_status != Nurse.EmploymentStatus.PENDING:
            raise ValidationError("This employment record has already been decided.")

        nurse.employment_status = Nurse.EmploymentStatus.REJECTED
        nurse.employment_decided_at = timezone.now()
        nurse.employment_decided_by = request.user

        nurse.save(update_fields=[
            "employment_status",
            "employment_decided_at",
            "employment_decided_by",
            "updated_at",
        ])

    return Response(NurseProfileSerializer(nurse, context={"request": request}).data)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def renew_nurse(request):
    nurse = getattr(request.user, "nurse_profile", None)
    if not nurse:
        raise PermissionDenied
    if nurse.record_status != Nurse.RecordStatus.APPROVED:
        raise PermissionDenied("Renewals are available after registration approval.")
    expiry = parse_date(request.data.get("licence_expiry") or "")
    if not expiry or expiry <= timezone.localdate():
        raise ValidationError({"licence_expiry": "Enter a future licence expiry date."})
    upload = request.FILES.get("file")
    if not upload:
        raise ValidationError({"file": "Upload a licence document."})
    from registry.forms import _validate_upload
    try:
        _validate_upload(upload, "Licence document", allow_pdf=True)
    except Exception as exc:
        raise ValidationError({"file": str(exc)}) from exc
    document = LicenceDocument.objects.create(
        nurse=nurse, file=upload, document_type=LicenceDocument.DocumentType.RENEWAL,
        proposed_expiry=expiry,
    )
    return Response({"id": document.pk, "decision": document.decision, "document_type": document.document_type}, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def nurse_activity(request):
    nurse = getattr(request.user, "nurse_profile", None)
    if not nurse:
        raise PermissionDenied
    documents = list(nurse.documents.values("id", "document_type", "uploaded_at", "decision", "reason", "proposed_expiry"))
    reminders = list(nurse.notifications.values("id", "type", "licence_expiry", "sent_at", "status"))
    return Response({"documents": documents, "notifications": reminders})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def renewal_queue(request):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied
    rows = LicenceDocument.objects.filter(
        document_type=LicenceDocument.DocumentType.RENEWAL,
        decision=LicenceDocument.Decision.PENDING,
    ).select_related("nurse", "nurse__employer")
    return Response([{
        "id": row.pk, "nurse_id": row.nurse_id, "name": row.nurse.full_name,
        "nanm_id": row.nurse.nanm_id, "employer": row.nurse.employer.name,
        "licence_number": row.nurse.licence_number,
        "proposed_expiry": row.proposed_expiry, "uploaded_at": row.uploaded_at,
    } for row in rows])


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def review_renewal(request, pk):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied
    document = LicenceDocument.objects.select_related("nurse").filter(
        pk=pk, document_type=LicenceDocument.DocumentType.RENEWAL,
        decision=LicenceDocument.Decision.PENDING,
    ).first()
    if not document:
        raise NotFound("Pending renewal not found.")
    action = request.data.get("action")
    if action not in {"approve", "reject"}:
        raise ValidationError({"action": "Choose approve or reject."})
    reason = (request.data.get("reason") or "").strip()
    if action == "reject" and not reason:
        raise ValidationError({"reason": "Provide a reason for rejecting this renewal."})
    with transaction.atomic():
        document.decision = LicenceDocument.Decision.APPROVED if action == "approve" else LicenceDocument.Decision.REJECTED
        document.reason = reason
        document.reviewed_by = request.user
        document.reviewed_at = timezone.now()
        document.save(update_fields=["decision", "reason", "reviewed_by", "reviewed_at"])
        if action == "approve" and document.proposed_expiry:
            document.nurse.licence_expiry = document.proposed_expiry
            document.nurse.save(update_fields=["licence_expiry", "updated_at"])
    return Response({"id": document.pk, "decision": document.decision, "reason": document.reason})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_dashboard_summary(request):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied
    from datetime import timedelta
    from django.conf import settings
    today = timezone.localdate()
    nurses = Nurse.objects.all()
    valid = nurses.filter(record_status=Nurse.RecordStatus.APPROVED, licence_expiry__gte=today)
    warning_date = today + timedelta(days=settings.LICENCE_EXPIRY_WARNING_DAYS)
    return Response({
        "total_nurses": nurses.count(),
        "pending_nurses": nurses.filter(record_status=Nurse.RecordStatus.PENDING).count(),
        "active_licences": valid.filter(licence_expiry__gt=warning_date).count(),
        "expiring_licences": valid.filter(licence_expiry__lte=warning_date).count(),
        "expired_licences": nurses.filter(record_status=Nurse.RecordStatus.APPROVED, licence_expiry__lt=today).count(),
        "restricted_nurses": nurses.filter(record_status__in=[Nurse.RecordStatus.SUSPENDED, Nurse.RecordStatus.REVOKED]).count(),
        "pending_hr_registrations": HRRegistrationRequest.objects.filter(status=HRRegistrationRequest.Status.PENDING).count(),
        "pending_renewals": LicenceDocument.objects.filter(document_type=LicenceDocument.DocumentType.RENEWAL, decision=LicenceDocument.Decision.PENDING).count(),
        "recent_nurses": list(nurses.select_related("employer").values(
            "id", "full_name", "nanm_id", "employer__name", "record_status", "created_at"
        )[:5]),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def nurse_card(request):
    from django.conf import settings
    nurse = getattr(request.user, "nurse_profile", None)
    if not nurse:
        raise PermissionDenied
    if nurse.record_status != Nurse.RecordStatus.APPROVED or not nurse.nanm_id:
        return Response({"available": False, "record_status": nurse.record_status}, status=status.HTTP_200_OK)
    token = signing.dumps({"nurse_id": nurse.pk}, salt=settings.CARD_LINK_SALT)
    signed_path = reverse("registry:signed_card", args=[token])
    verify_path = reverse("registry:nurse_qr", args=[nurse.nanm_id])
    return Response({
        "available": True,
        "signed_url": request.build_absolute_uri(signed_path),
        "qr_url": request.build_absolute_uri(verify_path),
        "nurse": NurseProfileSerializer(nurse, context={"request": request}).data,
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def register_hr(request):
    form = HRRegistrationForm(request.data)
    if not form.is_valid():
        raise ValidationError(form.errors)
    application = form.save()
    return Response({"id": application.pk, "status": application.status}, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([AllowAny])
def employer_options(request):
    return Response(list(Employer.objects.filter(approved=True).values("id", "name", "type", "lga")))


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def hr_review_queue(request):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied
    rows = HRRegistrationRequest.objects.filter(status=HRRegistrationRequest.Status.PENDING).values(
        "id", "email", "hospital_name", "employer_type", "lga", "contact_email", "created_at"
    )
    return Response(list(rows))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def review_hr_registration(request, pk):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied
    application = HRRegistrationRequest.objects.filter(pk=pk, status=HRRegistrationRequest.Status.PENDING).first()
    if not application:
        raise NotFound("Pending registration not found.")
    action = request.data.get("action")
    if action not in {"approve", "reject"}:
        raise ValidationError({"action": "Choose approve or reject."})
    if action == "approve":
        with transaction.atomic():
            employer, _ = Employer.objects.get_or_create(
                name=application.hospital_name,
                defaults={"type": application.employer_type, "lga": application.lga,
                          "contact_email": application.contact_email, "approved": True},
            )
            username = application.email.split("@", 1)[0]
            user = User.objects.filter(email__iexact=application.email).first()
            if user is None:
                if User.objects.filter(username__iexact=username).exists():
                    username = application.email
                if User.objects.filter(username__iexact=username).exists():
                    raise ValidationError({"email": "Could not allocate a unique username for this account."})
                user = User.objects.create_user(username=username, email=application.email)
            user.email = application.email
            user.password = application.password
            user.is_staff = True
            user.save()
            from django.contrib.auth.models import Group
            group, _ = Group.objects.get_or_create(name=HR)
            user.groups.add(group)
            employer.hr_users.add(user)
            application.status = HRRegistrationRequest.Status.APPROVED
    else:
        application.status = HRRegistrationRequest.Status.REJECTED
        application.reason = (request.data.get("reason") or "No reason provided").strip()
    application.reviewed_by = request.user
    application.reviewed_at = timezone.now()
    application.save(update_fields=["status", "reason", "reviewed_by", "reviewed_at", "updated_at"])
    return Response({"id": application.pk, "status": application.status})


def _require_super_admin(user):
    if not is_super_admin(user):
        raise PermissionDenied("Only super admins can manage registry accounts and corrections.")


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


def _nurse_admin_data(nurse, request):
    return {
        "id": nurse.pk, "nanm_id": nurse.nanm_id, "full_name": nurse.full_name,
        "email": nurse.email, "phone": nurse.phone, "nin_last4": nurse.nin_last4,
        "user_is_active": nurse.user.is_active if nurse.user_id else False,
        "photo_url": request.build_absolute_uri(nurse.photo.url) if nurse.photo else "",
        "licence_number": nurse.licence_number, "licence_expiry": nurse.licence_expiry,
        "specialty": nurse.specialty, "cadre": nurse.cadre,
        "employer_id": nurse.employer_id, "employer": nurse.employer.name,
        "ward": nurse.ward, "record_status": nurse.record_status,
        "created_at": nurse.created_at, "updated_at": nurse.updated_at,
        "documents": [{
            "id": doc.pk, "document_type": doc.document_type, "decision": doc.decision,
            "uploaded_at": doc.uploaded_at,
            "content_path": reverse("admin_document_content", args=[doc.pk]) if doc.file else "",
        } for doc in nurse.documents.all()],
    }


@api_view(["GET", "POST", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def admin_nurses(request, pk=None):
    if not is_staff_reviewer(request.user):
        raise PermissionDenied
    if request.method == "POST" and not pk:
        _require_super_admin(request.user)
        email = serializers.EmailField().run_validation(request.data.get("email", ""))
        password = request.data.get("password") or ""
        if len(password) < 12:
            raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
        if User.objects.filter(email__iexact=email).exists() or User.objects.filter(username__iexact=email).exists():
            raise ValidationError({"email": "An account already exists for this email."})
        employer = Employer.objects.filter(pk=request.data.get("employer"), approved=True).first()
        if not employer:
            raise ValidationError({"employer": "Choose an approved employer."})
        expiry = parse_date(request.data.get("licence_expiry") or "")
        if not expiry:
            raise ValidationError({"licence_expiry": "Enter a valid date."})
        if request.data.get("nin"):
            raw_nin = str(request.data["nin"]).strip()
            if not raw_nin.isdigit() or len(raw_nin) != 11:
                raise ValidationError({"nin": "NIN must contain 11 digits."})
            from registry.crypto import hash_nin
            if Nurse.objects.filter(nin_hash=hash_nin(raw_nin)).exists():
                raise ValidationError({"nin": "This NIN is already associated with another record."})
        photo = request.FILES.get("photo")
        scan = request.FILES.get("licence_scan")
        from registry.forms import _validate_upload
        try:
            if photo:
                _validate_upload(photo, "Nurse photo", allow_pdf=False)
            if scan:
                _validate_upload(scan, "Licence document", allow_pdf=True)
        except DjangoValidationError as exc:
            raise ValidationError(exc.messages) from exc
        user = User.objects.create_user(username=email, email=email, password=password)
        nurse = Nurse(
            user=user, full_name=(request.data.get("full_name") or "").strip(),
            email=email, phone=(request.data.get("phone") or "").strip(),
            licence_number=(request.data.get("licence_number") or "").strip(),
            licence_expiry=expiry, specialty=(request.data.get("specialty") or "").strip(),
            cadre=(request.data.get("cadre") or "").strip(), employer=employer,
            ward=(request.data.get("ward") or "").strip(), photo=photo,
            record_status=Nurse.RecordStatus.PENDING,
        )
        if not nurse.full_name or not nurse.phone or not nurse.licence_number:
            user.delete()
            raise ValidationError("Full name, phone and licence number are required.")
        if request.data.get("nin"):
            nurse.set_nin(raw_nin)
        nurse.save()
        if scan:
            LicenceDocument.objects.create(nurse=nurse, file=scan, document_type=LicenceDocument.DocumentType.INITIAL)
        return Response(_nurse_admin_data(nurse, request), status=status.HTTP_201_CREATED)
    if request.method == "GET":
        rows = Nurse.objects.select_related("employer", "user").prefetch_related("documents")
        search = (request.query_params.get("search") or "").strip()
        status_filter = (request.query_params.get("status") or "").strip()
        employer_id = (request.query_params.get("employer") or "").strip()
        if search:
            from django.db.models import Q
            rows = rows.filter(Q(full_name__icontains=search) | Q(email__icontains=search) |
                               Q(phone__icontains=search) | Q(nanm_id__icontains=search) |
                               Q(licence_number__icontains=search) | Q(employer__name__icontains=search))
        if status_filter:
            rows = rows.filter(record_status=status_filter)
        if employer_id.isdigit():
            rows = rows.filter(employer_id=int(employer_id))
        if pk:
            nurse = rows.filter(pk=pk).first()
            if not nurse:
                raise NotFound("Nurse record not found.")
            return Response(_nurse_admin_data(nurse, request))
        return Response([_nurse_admin_data(nurse, request) for nurse in rows])

    nurse = Nurse.objects.select_related("employer", "user").filter(pk=pk).first() if pk else None
    if not nurse:
        raise NotFound("Nurse record not found.")
    if request.method == "DELETE":
        _require_super_admin(request.user)
        stored_files = []
        if nurse.photo:
            stored_files.append((nurse.photo.storage, nurse.photo.name))
        stored_files.extend((doc.file.storage, doc.file.name) for doc in nurse.documents.all() if doc.file)
        with transaction.atomic():
            user = nurse.user
            nurse.delete()
            if user and not user.is_superuser and not user.groups.exists() and not user.is_staff:
                user.delete()
            elif user:
                user.is_active = False
                user.save(update_fields=["is_active"])
        for storage, name in stored_files:
            storage.delete(name)
        return Response(status=status.HTTP_204_NO_CONTENT)
    if request.method == "PATCH":
        _require_super_admin(request.user)
        fields = {"full_name", "email", "phone", "licence_number", "licence_expiry", "specialty", "cadre", "ward"}
        changed = []
        for field in fields & request.data.keys():
            value = request.data.get(field)
            if field == "email":
                value = serializers.EmailField().run_validation(value)
            if field == "licence_expiry":
                value = parse_date(value or "")
                if not value:
                    raise ValidationError({field: "Enter a valid date."})
            setattr(nurse, field, value)
            changed.append(field)
        if "employer" in request.data:
            employer = Employer.objects.filter(pk=request.data.get("employer"), approved=True).first()
            if not employer:
                raise ValidationError({"employer": "Choose an approved employer."})
            nurse.employer = employer
            changed.append("employer")
        if "nin" in request.data:
            raw_nin = (request.data.get("nin") or "").strip()
            if raw_nin and (not raw_nin.isdigit() or len(raw_nin) != 11):
                raise ValidationError({"nin": "NIN must contain 11 digits."})
            if raw_nin:
                from registry.crypto import hash_nin
                duplicate = Nurse.objects.exclude(pk=nurse.pk).filter(nin_hash=hash_nin(raw_nin)).exists()
                if duplicate:
                    raise ValidationError({"nin": "This NIN is already associated with another record."})
                nurse.set_nin(raw_nin)
                changed.append("nin")
        if request.FILES.get("photo"):
            from registry.forms import _validate_upload
            try:
                _validate_upload(request.FILES["photo"], "Nurse photo", allow_pdf=False)
            except DjangoValidationError as exc:
                raise ValidationError(exc.messages) from exc
            nurse.photo = request.FILES["photo"]
            changed.append("photo")
        if request.FILES.get("licence_scan"):
            from registry.forms import _validate_upload
            upload = request.FILES["licence_scan"]
            try:
                _validate_upload(upload, "Licence document", allow_pdf=True)
            except Exception as exc:
                raise ValidationError({"licence_scan": str(exc)}) from exc
            document_id = request.data.get("document_id")
            document = nurse.documents.filter(pk=document_id).first() if document_id else None
            if document:
                document.file = upload
                document.decision = LicenceDocument.Decision.PENDING
                document.reason = ""
                document.reviewed_by = None
                document.reviewed_at = None
                document.save(update_fields=["file", "decision", "reason", "reviewed_by", "reviewed_at"])
            else:
                LicenceDocument.objects.create(nurse=nurse, file=upload, document_type=LicenceDocument.DocumentType.INITIAL)
            changed.append("licence_scan")
        user = getattr(nurse, "user", None)
        if not user and request.data.get("password"):
            password = request.data["password"]
            if len(password) < 12:
                raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
            if User.objects.filter(email__iexact=nurse.email).exists() or User.objects.filter(username__iexact=nurse.email).exists():
                raise ValidationError({"email": "An account already exists for this email."})
            user = User.objects.create_user(username=nurse.email, email=nurse.email, password=password)
            nurse.user = user
        if user and "email" in changed:
            duplicate = User.objects.exclude(pk=user.pk).filter(email__iexact=nurse.email).exists()
            if duplicate:
                raise ValidationError({"email": "Another account already uses this email."})
            old_username = user.username
            if "@" in old_username and User.objects.exclude(pk=user.pk).filter(username__iexact=nurse.email).exists():
                raise ValidationError({"email": "Another account already uses this email as its username."})
            user.email = nurse.email
            if "@" in old_username:
                user.username = nurse.email
            user.save(update_fields=["email", "username"])
        if user and request.data.get("password"):
            password = request.data["password"]
            if len(password) < 12:
                raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
            user.set_password(password)
        if user and "is_active" in request.data:
            user.is_active = _as_bool(request.data.get("is_active"))
        if user and (request.data.get("password") or "is_active" in request.data or "email" in changed):
            user.save()
        nurse.save()
        return Response(_nurse_admin_data(nurse, request))

    action = request.data.get("action")
    target_status = {"approve": Nurse.RecordStatus.APPROVED, "reject": Nurse.RecordStatus.REJECTED,
                     "flag": Nurse.RecordStatus.FLAGGED, "suspend": Nurse.RecordStatus.SUSPENDED,
                     "revoke": Nurse.RecordStatus.REVOKED, "reinstate": Nurse.RecordStatus.APPROVED,
                     "reopen": Nurse.RecordStatus.PENDING}.get(action)
    if not target_status:
        raise ValidationError({"action": "Choose a valid review action."})
    try:
        nurse = transition_nurse(request.user, nurse, target_status, request.data.get("reason", ""))
    except DjangoValidationError as exc:
        raise ValidationError(getattr(exc, "message_dict", None) or exc.messages) from exc
    return Response(_nurse_admin_data(nurse, request))


@api_view(["GET", "POST", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def admin_hr_users(request, pk=None):
    _require_super_admin(request.user)
    hr_group, _ = Group.objects.get_or_create(name=HR)
    users = User.objects.filter(groups=hr_group).prefetch_related("employers")
    search = (request.query_params.get("search") or "").strip()
    if search:
        from django.db.models import Q
        users = users.filter(Q(email__icontains=search) | Q(employers__name__icontains=search) |
                             Q(first_name__icontains=search) | Q(last_name__icontains=search)).distinct()
    if request.method == "GET":
        return Response([{
            "id": user.pk, "email": user.email, "first_name": user.first_name,
            "last_name": user.last_name, "is_active": user.is_active,
            "employers": list(user.employers.values("id", "name", "type", "lga", "contact_email", "approved")),
        } for user in users])
    if request.method == "POST":
        email = serializers.EmailField().run_validation(request.data.get("email", ""))
        password = request.data.get("password") or ""
        if len(password) < 12:
            raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
        if User.objects.filter(email__iexact=email).exists() or User.objects.filter(username__iexact=email).exists():
            raise ValidationError({"email": "An account already exists for this email."})
        employer_data = request.data.get("employer") or {}
        if not employer_data.get("name") or not employer_data.get("lga"):
            raise ValidationError({"employer": "Hospital name and LGA are required."})
        with transaction.atomic():
            employer = Employer.objects.create(
                name=employer_data["name"].strip(), type=employer_data.get("type", Employer.Type.HOSPITAL),
                lga=employer_data["lga"].strip(), contact_email=employer_data.get("contact_email", ""),
                approved=employer_data.get("approved", True),
            )
            user = User.objects.create_user(
                username=email, email=email, password=password,
                first_name=(request.data.get("first_name") or "").strip(),
                last_name=(request.data.get("last_name") or "").strip(), is_staff=True,
            )
            user.groups.add(hr_group)
            employer.hr_users.add(user)
        return Response({"id": user.pk, "email": user.email, "first_name": user.first_name,
                         "last_name": user.last_name, "is_active": user.is_active,
                         "employers": list(user.employers.values("id", "name", "type", "lga", "contact_email", "approved"))},
                        status=status.HTTP_201_CREATED)
    user = users.filter(pk=pk or request.data.get("id")).first()
    if not user:
        raise NotFound("Hospital HR account not found.")
    if request.method == "DELETE":
        with transaction.atomic():
            user.employers.remove(*user.employers.all())
            user.groups.remove(hr_group)
            if not user.groups.exists() and not user.is_superuser:
                user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    if "email" in request.data:
        email = serializers.EmailField().run_validation(request.data["email"])
        if User.objects.exclude(pk=user.pk).filter(email__iexact=email).exists():
            raise ValidationError({"email": "Another account already uses this email."})
        if User.objects.exclude(pk=user.pk).filter(username__iexact=email).exists():
            raise ValidationError({"email": "Another account already uses this email as its username."})
        user.username = email
    for field in ("email", "first_name", "last_name", "is_active"):
        if field in request.data:
            value = request.data.get(field)
            setattr(user, field, _as_bool(value) if field == "is_active" else value)
    if request.data.get("password"):
        if len(request.data["password"]) < 12:
            raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
        user.set_password(request.data["password"])
    user.save()
    employer_data = request.data.get("employer")
    if employer_data:
        employer = user.employers.first()
        if not employer:
            raise ValidationError({"employer": "This HR account is not attached to an employer."})
        for field in ("name", "type", "lga", "contact_email", "approved"):
            if field in employer_data:
                setattr(employer, field, employer_data[field])
        employer.save()
    return Response({"id": user.pk, "email": user.email, "first_name": user.first_name,
                     "last_name": user.last_name, "is_active": user.is_active,
                     "employers": list(user.employers.values("id", "name", "type", "lga", "contact_email", "approved"))})


@api_view(["GET", "POST", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def admin_supervisors(request, pk=None):
    _require_super_admin(request.user)
    group, _ = Group.objects.get_or_create(name=SUPERVISOR)
    if request.method == "GET":
        users = User.objects.filter(groups=group)
        if pk:
            users = users.filter(pk=pk)
        return Response(list(users.values("id", "email", "first_name", "last_name", "is_active")))
    if request.method in {"PATCH", "DELETE"}:
        user = User.objects.filter(groups=group, pk=pk).first()
        if not user:
            raise NotFound("Supervisor account not found.")
        if request.method == "DELETE":
            user.groups.remove(group)
            if not user.groups.exists() and not user.is_superuser:
                user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        if "email" in request.data:
            email = serializers.EmailField().run_validation(request.data["email"])
            if User.objects.exclude(pk=user.pk).filter(email__iexact=email).exists() or User.objects.exclude(pk=user.pk).filter(username__iexact=email).exists():
                raise ValidationError({"email": "Another account already uses this email."})
            user.email = user.username = email
        for field in ("first_name", "last_name", "is_active"):
            if field in request.data:
                value = request.data.get(field)
                setattr(user, field, _as_bool(value) if field == "is_active" else value)
        if request.data.get("password"):
            if len(request.data["password"]) < 12:
                raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
            user.set_password(request.data["password"])
        user.save()
        return Response({"id": user.pk, "email": user.email, "first_name": user.first_name,
                         "last_name": user.last_name, "is_active": user.is_active})
    email = (request.data.get("email") or "").strip().lower()
    password = request.data.get("password") or ""
    if not email or "@" not in email:
        raise ValidationError({"email": "Enter a valid email address."})
    if len(password) < 12:
        raise ValidationError({"password": "Use a temporary password with at least 12 characters."})
    if User.objects.filter(email__iexact=email).exists() or User.objects.filter(username__iexact=email).exists():
        raise ValidationError({"email": "An account already exists for this email."})
    user = User.objects.create_user(username=email, email=email, password=password,
                                    first_name=(request.data.get("first_name") or "").strip(),
                                    last_name=(request.data.get("last_name") or "").strip(), is_staff=True)
    user.groups.add(group)
    return Response({"id": user.pk, "email": user.email, "first_name": user.first_name,
                     "last_name": user.last_name, "is_active": user.is_active}, status=status.HTTP_201_CREATED)
