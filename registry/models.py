from django.conf import settings
from django.contrib.auth.hashers import identify_hasher, make_password
from django.core.exceptions import ValidationError
from django.db import models


class Employer(models.Model):
    class Type(models.TextChoices):
        HOSPITAL = "hospital", "Hospital"
        PRIMARY_HEALTH_CENTRE = "primary_health_centre", "Primary health centre"
        CLINIC = "clinic", "Clinic"
        OTHER = "other", "Other"
        UNEMPLOYED = "unemployed", "Unemployed"

    name = models.CharField(max_length=255)
    type = models.CharField(max_length=32, choices=Type.choices, default=Type.HOSPITAL)
    lga = models.CharField(max_length=120)
    contact_email = models.EmailField(blank=True)
    approved = models.BooleanField(default=False)
    hr_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="employers",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Nurse(models.Model):
    class RecordStatus(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        FLAGGED = "flagged", "Flagged"
        SUSPENDED = "suspended", "Suspended"
        REVOKED = "revoked", "Revoked"

    class EmploymentStatus(models.TextChoices):
        PENDING = "pending", "Pending"
        CONFIRMED = "confirmed", "Confirmed"
        REJECTED = "rejected", "Rejected"

    nanm_id = models.CharField(max_length=32, unique=True, null=True, blank=True)
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=32)
    email = models.EmailField()
    nin_encrypted = models.TextField(blank=True)
    nin_last4 = models.CharField(max_length=4, blank=True)
    nin_hash = models.CharField(max_length=64, blank=True, db_index=True)
    photo = models.ImageField(upload_to="nurse_photos/", blank=True)
    licence_number = models.CharField(max_length=120)
    licence_expiry = models.DateField()
    specialty = models.CharField(max_length=120, blank=True)
    cadre = models.CharField(max_length=120, blank=True)
    employer = models.ForeignKey(
        Employer, on_delete=models.PROTECT, related_name="nurses"
    )
    ward = models.CharField(max_length=120, blank=True)
    record_status = models.CharField(
        max_length=16,
        choices=RecordStatus.choices,
        default=RecordStatus.PENDING,
    )
    consent_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_nurses",
        null=True,
        blank=True,
    )
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="nurse_profile",
        null=True,
        blank=True,
    )
    employer_confirmed_at = models.DateTimeField(null=True, blank=True)
    employer_confirmed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="confirmed_nurses",
        null=True,
        blank=True,
    )
    employment_status = models.CharField(
        max_length=12,
        choices=EmploymentStatus.choices,
        default=EmploymentStatus.PENDING,
    )
    employment_decided_at = models.DateTimeField(null=True, blank=True)
    employment_decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="employment_decisions",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["licence_expiry"], name="nurse_expiry_idx"),
            models.Index(fields=["record_status"], name="nurse_status_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    record_status__in=[
                        "pending",
                        "approved",
                        "rejected",
                        "flagged",
                        "suspended",
                        "revoked",
                    ]
                ),
                name="valid_nurse_record_status",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(record_status="approved", nanm_id__isnull=False)
                    | ~models.Q(record_status="approved")
                ),
                name="approved_nurse_requires_nanm_id",
            ),
        ]

    def __str__(self):
        return self.nanm_id or self.full_name

    @property
    def reference(self):
        return f"REQ-{self.pk:06d}"

    @property
    def nin_masked(self):
        return f"*******{self.nin_last4}" if self.nin_last4 else ""

    def set_nin(self, raw_nin):
        from .crypto import encrypt_nin, hash_nin

        raw_nin = (raw_nin or "").strip()
        if not raw_nin:
            self.nin_encrypted = ""
            self.nin_last4 = ""
            self.nin_hash = ""
            return
        self.nin_encrypted = encrypt_nin(raw_nin)
        self.nin_last4 = raw_nin[-4:]
        self.nin_hash = hash_nin(raw_nin)

    def get_nin(self):
        from .crypto import decrypt_nin

        return decrypt_nin(self.nin_encrypted)

    def save(self, *args, **kwargs):
        # Enforce that the NANNM ID cannot be changed once issued
        if self.pk:
            try:
                original = Nurse.objects.get(pk=self.pk)
                if original.nanm_id and original.nanm_id != self.nanm_id:
                    raise ValidationError(
                        {"nanm_id": "The NANNM ID is immutable once issued."}
                    )
            except Nurse.DoesNotExist:
                pass
        super().save(*args, **kwargs)

    @property
    def licence_status_level(self):
        """Return a normalized internal state for UI and filtering: green, yellow, red, grey, black."""
        from django.utils import timezone

        today = timezone.localdate()
        if self.record_status == self.RecordStatus.PENDING:
            return "grey"
        if self.record_status == self.RecordStatus.REJECTED:
            return "grey"
        if self.record_status == self.RecordStatus.FLAGGED:
            return "black"
        if self.record_status == self.RecordStatus.SUSPENDED:
            return "red"
        if self.record_status == self.RecordStatus.REVOKED:
            return "black"
        if self.licence_expiry < today:
            return "red"
        if (self.licence_expiry - today).days <= settings.LICENCE_EXPIRY_WARNING_DAYS:
            return "yellow"
        return "green"

    @property
    def licence_status_band(self):
        """Return a normalized status band: green / yellow / red / grey / black."""
        from django.utils import timezone

        today = timezone.localdate()
        if self.record_status == "pending":
            return "grey"
        if self.record_status == "rejected":
            return "grey"
        if self.record_status == "flagged":
            return "black"
        if self.record_status in {"suspended", "revoked"}:
            return "red"
        if self.record_status != "approved":
            return "grey"
        if self.licence_expiry < today:
            return "red"
        if (self.licence_expiry - today).days <= settings.LICENCE_EXPIRY_WARNING_DAYS:
            return "yellow"
        return "green"

    @property
    def public_licence_status(self):
        from django.utils import timezone

        today = timezone.localdate()
        if self.record_status in {"flagged", "suspended", "revoked"}:
            return self.get_record_status_display()
        if self.record_status == "pending":
            return "Pending"
        if self.record_status == "rejected":
            return "Rejected"
        if self.licence_expiry < today:
            return "Expired"
        if (self.licence_expiry - today).days <= settings.LICENCE_EXPIRY_WARNING_DAYS:
            return "Expiring soon"
        return "Licensed"


class LicenceDocument(models.Model):
    class DocumentType(models.TextChoices):
        INITIAL = "initial", "Initial"
        RENEWAL = "renewal", "Renewal"

    class Decision(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    nurse = models.ForeignKey(Nurse, on_delete=models.CASCADE, related_name="documents")
    file = models.FileField(upload_to="licence_scans/%Y/%m/")
    proposed_expiry = models.DateField(null=True, blank=True)
    document_type = models.CharField(
        max_length=16,
        choices=DocumentType.choices,
        default=DocumentType.INITIAL,
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="reviewed_documents",
        null=True,
        blank=True,
    )
    decision = models.CharField(
        max_length=16,
        choices=Decision.choices,
        default=Decision.PENDING,
    )
    reason = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"{self.nurse} - {self.get_document_type_display()}"


class Flag(models.Model):
    nurse = models.ForeignKey(Nurse, on_delete=models.CASCADE, related_name="flags")
    reason = models.TextField()
    raised_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="raised_flags",
    )
    raised_at = models.DateTimeField(auto_now_add=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="resolved_flags",
        null=True,
        blank=True,
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution = models.TextField(blank=True)

    class Meta:
        ordering = ["-raised_at"]

    def __str__(self):
        return f"Flag for {self.nurse}"


class Notification(models.Model):
    class Type(models.TextChoices):
        EXPIRY_REMINDER = "expiry_reminder", "Expiry reminder"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"

    nurse = models.ForeignKey(
        Nurse, on_delete=models.CASCADE, related_name="notifications"
    )
    type = models.CharField(max_length=32, choices=Type.choices)
    licence_expiry = models.DateField()
    sent_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["nurse", "type", "licence_expiry"],
                name="unique_nurse_notification",
            )
        ]

    def __str__(self):
        return f"{self.get_type_display()} for {self.nurse}"


class HRRegistrationRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    email = models.EmailField(unique=True)
    hospital_name = models.CharField(max_length=255)
    employer_type = models.CharField(
        max_length=32, choices=Employer.Type.choices, default=Employer.Type.HOSPITAL
    )
    lga = models.CharField(max_length=120)
    contact_email = models.EmailField(blank=True)
    password = models.CharField(max_length=128)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="reviewed_hr_registrations",
        null=True,
        blank=True,
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.email} ({self.status})"

    def save(self, *args, **kwargs):
        if self.password:
            try:
                identify_hasher(self.password)
            except ValueError:
                self.password = make_password(self.password)
        super().save(*args, **kwargs)
