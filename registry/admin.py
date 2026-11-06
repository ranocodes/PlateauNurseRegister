from django.contrib import admin, messages
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.html import format_html
from django.utils import timezone

from .forms import ReasonForm
from .models import Employer, Flag, LicenceDocument, Notification, Nurse, HRRegistrationRequest
from .permissions import is_hr
from .services import approve_nurse, flag_nurse, reject_nurse


class LicenceDocumentInline(admin.TabularInline):
    model = LicenceDocument
    extra = 0
    readonly_fields = ("uploaded_at", "reviewed_at", "preview")
    fields = (
        "file",
        "document_type",
        "decision",
        "reason",
        "reviewed_by",
        "reviewed_at",
        "uploaded_at",
        "preview",
    )

    @admin.display(description="Preview")
    def preview(self, obj):
        if not obj.pk or not obj.file:
            return "-"
        return format_html(
            '<a href="{}" target="_blank" rel="noopener">View file</a>',
            reverse("registry:protected_document", args=[obj.pk]),
        )


class FlagInline(admin.TabularInline):
    model = Flag
    extra = 0
    readonly_fields = ("raised_at",)
    fields = (
        "reason",
        "raised_by",
        "raised_at",
        "resolved_by",
        "resolved_at",
        "resolution",
    )


@admin.register(Nurse)
class NurseAdmin(admin.ModelAdmin):
    list_display = (
        "nanm_id",
        "full_name",
        "record_status",
        "licence_expiry",
        "employer",
        "possible_duplicate",
    )
    list_filter = ("record_status", "employer", "licence_expiry")
    search_fields = ("nanm_id", "full_name", "licence_number", "phone")
    date_hierarchy = "licence_expiry"
    readonly_fields = (
        "nanm_id",
        "nin_last4",
        "record_status",
        "created_at",
        "updated_at",
        "consent_at",
        "created_by",
        "employer_confirmed_at",
        "employer_confirmed_by",
    )
    inlines = (LicenceDocumentInline, FlagInline)
    actions = ("approve_selected", "reject_selected", "flag_selected", "export_csv")

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if is_hr(request.user):
            return qs.filter(employer__hr_users=request.user).distinct()
        return qs

    def has_view_permission(self, request, obj=None):
        if is_hr(request.user):
            if obj is None:
                return True
            return obj.employer_id and obj.employer.hr_users.filter(pk=request.user.pk).exists()
        return super().has_view_permission(request, obj)

    def has_change_permission(self, request, obj=None):
        if is_hr(request.user):
            return False
        return super().has_change_permission(request, obj)

    def has_add_permission(self, request):
        if is_hr(request.user):
            return False
        return super().has_add_permission(request)

    def has_delete_permission(self, request, obj=None):
        if is_hr(request.user):
            return False
        return super().has_delete_permission(request, obj)

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if is_hr(request.user):
            extra = {
                "full_name",
                "phone",
                "email",
                "photo",
                "licence_number",
                "licence_expiry",
                "specialty",
                "cadre",
                "employer",
                "ward",
                "nanm_id",
                "record_status",
                "consent_at",
                "created_by",
                "created_at",
                "updated_at",
                "employer_confirmed_at",
                "employer_confirmed_by",
                "nin_last4",
            }
            fields.extend(sorted(extra - set(fields)))
        return tuple(fields)

    def get_fieldsets(self, request, obj=None):
        if is_hr(request.user):
            return (
                (
                    "Identity",
                    {"fields": ("full_name", "nanm_id", "photo")},
                ),
                (
                    "Employment",
                    {
                        "fields": (
                            "employer",
                            "ward",
                            "cadre",
                            "specialty",
                            "employer_confirmed_at",
                            "employer_confirmed_by",
                        )
                    },
                ),
                (
                    "Status",
                    {"fields": ("record_status", "licence_expiry")},
                ),
            )
        return super().get_fieldsets(request, obj)

    @admin.action(description="Approve selected nurse")
    def approve_selected(self, request, queryset):
        if queryset.count() != 1:
            messages.error(request, "Select exactly one nurse to approve.")
            return
        nurse = queryset.first()
        if nurse.record_status != Nurse.RecordStatus.PENDING:
            messages.error(request, "Only pending nurses can be approved.")
            return
        if request.POST.get("post") == "yes":
            approve_nurse(request.user, nurse.pk)
            messages.success(request, "Nurse approved and NANNM ID issued.")
            return redirect("registry:nurse_detail", pk=nurse.pk)
        return TemplateResponse(
            request,
            "admin_review_confirm.html",
            {"title": "Approve nurse", "nurse": nurse, "action": "approve", "reason_required": False},
        )

    @admin.action(description="Reject selected nurse(s)")
    def reject_selected(self, request, queryset):
        if request.POST.get("post"):
            reason = request.POST.get("reason", "").strip()
            if not reason:
                messages.error(request, "A reason is required for rejection.")
                return
            for nurse in queryset:
                if nurse.record_status != Nurse.RecordStatus.PENDING:
                    messages.warning(request, f"Nurse {nurse.nanm_id} is not pending; skipping.")
                    continue
                reject_nurse(request.user, nurse.pk, reason)
            messages.success(request, "Selected nurses rejected.")
            return redirect("registry:nurse_changelist")
        return TemplateResponse(
            request,
            "admin_review_confirm.html",
            {"title": "Reject nurse(s)", "nurses": queryset, "action": "reject", "reason_required": True},
        )

    @admin.action(description="Flag selected nurse(s)")
    def flag_selected(self, request, queryset):
        if request.POST.get("post"):
            reason = request.POST.get("reason", "").strip()
            if not reason:
                messages.error(request, "A reason is required for flagging.")
                return
            for nurse in queryset:
                if nurse.record_status != Nurse.RecordStatus.PENDING:
                    messages.warning(request, f"Nurse {nurse.nanm_id} is not pending; skipping.")
                    continue
                flag_nurse(request.user, nurse.pk, reason)
            messages.success(request, "Selected nurses flagged.")
            return redirect("registry:nurse_changelist")
        return TemplateResponse(
            request,
            "admin_review_confirm.html",
            {"title": "Flag nurse(s)", "nurses": queryset, "action": "flag", "reason_required": True},
        )

    @admin.action(description="Export selected nurses as CSV")
    def export_csv(self, request, queryset):
        if not request.user.is_superuser and not request.user.groups.filter(name="Super Admin").exists():
            messages.error(request, "Only super admins may export nurse data.")
            return

        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "nanm_id",
            "full_name",
            "email",
            "phone",
            "licence_number",
            "licence_expiry",
            "record_status",
            "employer",
            "ward",
            "specialty",
            "cadre",
        ])
        for nurse in queryset:
            writer.writerow([
                nurse.nanm_id or "",
                nurse.full_name,
                nurse.email,
                nurse.phone,
                nurse.licence_number,
                nurse.licence_expiry,
                nurse.record_status,
                nurse.employer.name if nurse.employer else "",
                nurse.ward,
                nurse.specialty,
                nurse.cadre,
            ])

        response = HttpResponse(output.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="nurses_export.csv"'
        return response

    export_csv.short_description = "Export selected nurses as CSV"




    fieldsets = (
        (
            "Identity",
            {"fields": ("nanm_id", "full_name", "phone", "email", "nin_last4", "photo")},
        ),
        (
            "Licence",
            {"fields": ("licence_number", "licence_expiry", "specialty", "cadre")},
        ),
        (
            "Employment",
            {"fields": ("employer", "ward", "employer_confirmed_at", "employer_confirmed_by")},
        ),
        (
            "Status",
            {"fields": ("record_status", "consent_at", "created_by", "created_at", "updated_at")},
        ),
    )

    @admin.display(boolean=True, description="Possible duplicate")
    def possible_duplicate(self, obj):
        if obj.nin_hash and Nurse.objects.filter(nin_hash=obj.nin_hash).exclude(pk=obj.pk).exists():
            return True
        if obj.licence_number and Nurse.objects.filter(licence_number__iexact=obj.licence_number).exclude(pk=obj.pk).exists():
            return True
        return False


@admin.register(Employer)
class EmployerAdmin(admin.ModelAdmin):
    list_display = ("name", "type", "lga", "approved")
    list_filter = ("type", "approved", "lga")
    search_fields = ("name", "lga", "contact_email")
    filter_horizontal = ("hr_users",)


@admin.register(LicenceDocument)
class LicenceDocumentAdmin(admin.ModelAdmin):
    list_display = ("nurse", "document_type", "decision", "uploaded_at", "preview")
    list_filter = ("document_type", "decision")
    search_fields = ("nurse__full_name", "nurse__nanm_id", "nurse__licence_number")
    readonly_fields = ("uploaded_at", "reviewed_at")
    raw_id_fields = ("nurse",)

    @admin.display(description="Preview")
    def preview(self, obj):
        if not obj.pk or not obj.file:
            return "-"
        return format_html(
            '<a href="{}" target="_blank" rel="noopener">View file</a>',
            reverse("registry:protected_document", args=[obj.pk]),
        )


@admin.register(Flag)
class FlagAdmin(admin.ModelAdmin):
    list_display = ("nurse", "raised_by", "raised_at", "resolved_at")
    list_filter = ("raised_at", "resolved_at")
    search_fields = ("nurse__full_name", "nurse__nanm_id", "reason")
    readonly_fields = ("raised_at",)
    raw_id_fields = ("nurse", "raised_by", "resolved_by")


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("nurse", "type", "licence_expiry", "status", "sent_at")
    list_filter = ("type", "status")
    search_fields = ("nurse__full_name", "nurse__nanm_id")
    raw_id_fields = ("nurse",)


@admin.register(HRRegistrationRequest)
class HRRegistrationRequestAdmin(admin.ModelAdmin):
    list_display = ("email", "hospital_name", "status", "created_at", "reviewed_by")
    list_filter = ("status", "employer_type", "lga")
    search_fields = ("email", "hospital_name", "lga")
    readonly_fields = ("created_at", "updated_at", "reviewed_at", "reviewed_by")
    actions = ["approve_selected", "reject_selected"]

    def approve_selected(self, request, queryset):
        if not request.user.is_superuser and not request.user.groups.filter(name="Super Admin").exists():
            messages.error(request, "Only super admins may approve HR registrations.")
            return
        approved = 0
        for registration in queryset.filter(status=HRRegistrationRequest.Status.PENDING):
            registration.status = HRRegistrationRequest.Status.APPROVED
            registration.reviewed_by = request.user
            registration.reviewed_at = timezone.now()
            registration.save(update_fields=["status", "reviewed_by", "reviewed_at", "updated_at"])
            approved += 1
        messages.success(request, f"Approved {approved} HR registration(s).")

    approve_selected.short_description = "Approve selected HR registrations"

    def reject_selected(self, request, queryset):
        if not request.user.is_superuser and not request.user.groups.filter(name="Super Admin").exists():
            messages.error(request, "Only super admins may reject HR registrations.")
            return
        rejected = 0
        for registration in queryset.filter(status=HRRegistrationRequest.Status.PENDING):
            registration.status = HRRegistrationRequest.Status.REJECTED
            registration.reviewed_by = request.user
            registration.reviewed_at = timezone.now()
            registration.reason = registration.reason or "No reason provided"
            registration.save(update_fields=["status", "reviewed_by", "reviewed_at", "reason", "updated_at"])
            rejected += 1
        messages.success(request, f"Rejected {rejected} HR registration(s).")

    reject_selected.short_description = "Reject selected HR registrations"
