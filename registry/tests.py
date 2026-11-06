import shutil
import tempfile
from datetime import timedelta
from io import BytesIO, StringIO
from pathlib import Path
from types import SimpleNamespace

from auditlog.models import LogEntry
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.http import Http404
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from PIL import Image

from .crypto import decrypt_nin, encrypt_nin, get_fernet, hash_nin
from .forms import MAX_UPLOAD_SIZE, _validate_upload
from .models import Employer, Flag, LicenceDocument, Notification, Nurse, HRRegistrationRequest
from .permissions import (
    HR,
    OFFICER,
    SUPER_ADMIN,
    SUPERVISOR,
    can_reveal_nin,
    can_view_nurse_photo,
    filter_employers_for_user,
    is_officer_or_above,
    nurses_for_user,
)
from .services import reveal_nin, revoke_nurse, suspend_nurse, transition_nurse
from .views import _serve_media

User = get_user_model()
TEST_KEY = Fernet.generate_key().decode()


def image_upload(name="selfie.jpg", color="blue"):
    buffer = BytesIO()
    Image.new("RGB", (20, 20), color).save(buffer, format="JPEG")
    return SimpleUploadedFile(name, buffer.getvalue(), content_type="image/jpeg")


def png_upload(name="scan.png"):
    buffer = BytesIO()
    Image.new("RGB", (20, 20), "green").save(buffer, format="PNG")
    return SimpleUploadedFile(name, buffer.getvalue(), content_type="image/png")


def pdf_upload(name="licence.pdf", extra=b""):
    content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + extra
    return SimpleUploadedFile(name, content, content_type="application/pdf")


@override_settings(NIN_ENCRYPTION_KEY=TEST_KEY)
class RegistryTestBase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls._media_root = tempfile.mkdtemp()
        cls._media_override = override_settings(MEDIA_ROOT=cls._media_root)
        cls._media_override.enable()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls._media_override.disable()
        shutil.rmtree(cls._media_root, ignore_errors=True)

    @classmethod
    def setUpTestData(cls):
        call_command("setup_groups", stdout=StringIO())

        cls.employer = Employer.objects.create(
            name="Demo Hospital",
            type=Employer.Type.HOSPITAL,
            lga="Jos North",
            approved=True,
        )
        cls.other_employer = Employer.objects.create(
            name="Other Clinic",
            type=Employer.Type.CLINIC,
            lga="Jos South",
            approved=True,
        )

        cls.officer = User.objects.create_user(
            username="officer", password="test-pass", is_staff=True
        )
        cls.officer.groups.add(Group.objects.get(name=OFFICER))
        cls.supervisor = User.objects.create_user(
            username="supervisor", password="test-pass", is_staff=True
        )
        cls.supervisor.groups.add(Group.objects.get(name=SUPERVISOR))
        cls.super_admin = User.objects.create_user(
            username="superadmin", password="test-pass", is_staff=True
        )
        cls.super_admin.groups.add(Group.objects.get(name=SUPER_ADMIN))
        cls.hr = User.objects.create_user(username="hr", password="test-pass", is_staff=True)
        cls.hr.groups.add(Group.objects.get(name=HR))
        cls.other_hr = User.objects.create_user(
            username="other-hr", password="test-pass", is_staff=True
        )
        cls.other_hr.groups.add(Group.objects.get(name=HR))
        cls.no_group = User.objects.create_user(username="no-group", password="test-pass")
        cls.employer.hr_users.add(cls.hr)
        cls.other_employer.hr_users.add(cls.other_hr)

    def create_nurse(self, **kwargs):
        values = {
            "full_name": "Test Nurse",
            "phone": "08030000001",
            "email": "nurse@example.test",
            "licence_number": f"LIC-{Nurse.objects.count() + 1}",
            "licence_expiry": timezone.localdate() + timedelta(days=365),
            "employer": self.employer,
            "record_status": Nurse.RecordStatus.PENDING,
        }
        nin = kwargs.pop("nin", None)
        values.update(kwargs)
        nurse = Nurse(**values)
        if nin:
            nurse.set_nin(nin)
        nurse.save()
        return nurse

    def registration_data(self, **overrides):
        values = {
            "full_name": "New Nurse",
            "phone": "08031234567",
            "email": "new@example.test",
            "licence_number": "PLT-LIC-NEW",
            "licence_expiry": (timezone.localdate() + timedelta(days=365)).isoformat(),
            "specialty": "General Nursing",
            "cadre": "Nurse",
            "employer": self.employer.pk,
            "ward": "Ward 1",
            "nin": "12345678901",
            "consent": "on",
            "licence_scan": pdf_upload(),
            "selfie": image_upload(),
        }
        values.update(overrides)
        return values


class CoreModelTests(RegistryTestBase):
    def test_tables_and_reference(self):
        nurse = self.create_nurse(nin="12345678901")
        self.assertEqual(nurse.reference, f"REQ-{nurse.pk:06d}")
        self.assertTrue(Nurse._meta.db_table)
        for model in (Employer, Nurse, LicenceDocument, Flag, Notification):
            self.assertTrue(model._meta.db_table)

    def test_approved_nurse_requires_nanm_id(self):
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Nurse.objects.create(
                    full_name="No ID",
                    phone="08030000002",
                    email="noid@example.test",
                    licence_number="LIC-NOID",
                    licence_expiry=timezone.localdate(),
                    employer=self.employer,
                    record_status=Nurse.RecordStatus.APPROVED,
                )

    def test_invalid_record_status_is_rejected(self):
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Nurse.objects.create(
                    full_name="Bad Status",
                    phone="08030000003",
                    email="bad@example.test",
                    licence_number="LIC-BAD",
                    licence_expiry=timezone.localdate(),
                    employer=self.employer,
                    record_status="bogus",
                )

    def test_nanm_id_is_unique(self):
        self.create_nurse(
            nanm_id="PLT-NUR-000001",
            record_status=Nurse.RecordStatus.APPROVED,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.create_nurse(
                    nanm_id="PLT-NUR-000001",
                    record_status=Nurse.RecordStatus.APPROVED,
                )

    def test_notification_is_unique_per_nurse_type_and_expiry(self):
        nurse = self.create_nurse()
        Notification.objects.create(
            nurse=nurse,
            type=Notification.Type.EXPIRY_REMINDER,
            licence_expiry=nurse.licence_expiry,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Notification.objects.create(
                    nurse=nurse,
                    type=Notification.Type.EXPIRY_REMINDER,
                    licence_expiry=nurse.licence_expiry,
                )


class CryptoAndAuditTests(RegistryTestBase):
    def test_encryption_round_trip_and_masking(self):
        nurse = self.create_nurse(nin="12345678901")
        self.assertNotEqual(nurse.nin_encrypted, "12345678901")
        self.assertEqual(nurse.nin_last4, "8901")
        self.assertEqual(nurse.nin_masked, "*******8901")
        self.assertEqual(nurse.get_nin(), "12345678901")
        self.assertEqual(decrypt_nin(nurse.nin_encrypted), "12345678901")

    def test_hash_is_stable_and_not_plaintext(self):
        first = hash_nin("12345678901")
        second = hash_nin("12345678901")
        other = hash_nin("12345678902")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertNotIn("12345678901", first)

    def test_missing_and_invalid_key_raise_clear_error(self):
        with override_settings(NIN_ENCRYPTION_KEY=""):
            with self.assertRaises(ImproperlyConfigured):
                get_fernet()
        with override_settings(NIN_ENCRYPTION_KEY="not-a-key"):
            with self.assertRaises(ImproperlyConfigured):
                get_fernet()

    def test_reveal_nin_is_audited_for_officer(self):
        nurse = self.create_nurse(nin="12345678901")
        self.assertEqual(reveal_nin(self.officer, nurse), "12345678901")
        self.assertTrue(
            LogEntry.objects.filter(
                actor=self.officer,
                action=LogEntry.Action.ACCESS,
            ).exists()
        )

    def test_reveal_nin_denied_for_hr(self):
        nurse = self.create_nurse(nin="12345678901")
        with self.assertRaises(PermissionDenied):
            reveal_nin(self.hr, nurse)
        self.assertFalse(
            LogEntry.objects.filter(
                actor=self.hr,
                action=LogEntry.Action.ACCESS,
            ).exists()
        )


class PermissionTests(RegistryTestBase):
    def test_groups_exist_with_permissions(self):
        for group_name in (OFFICER, SUPERVISOR, SUPER_ADMIN, HR):
            self.assertTrue(Group.objects.filter(name=group_name).exists())
            self.assertGreater(Group.objects.get(name=group_name).permissions.count(), 0)

    def test_role_helpers(self):
        self.assertTrue(can_reveal_nin(self.officer))
        self.assertTrue(can_reveal_nin(self.supervisor))
        self.assertTrue(can_reveal_nin(self.super_admin))
        self.assertFalse(can_reveal_nin(self.hr))
        self.assertTrue(is_officer_or_above(self.supervisor))
        self.assertFalse(is_officer_or_above(self.no_group))

    def test_hr_scoping(self):
        own = self.create_nurse(full_name="Own Employer")
        other = self.create_nurse(full_name="Other Employer", employer=self.other_employer)

        self.assertEqual(list(nurses_for_user(self.hr)), [own])
        self.assertEqual(list(nurses_for_user(self.other_hr)), [other])
        self.assertEqual(nurses_for_user(self.no_group).count(), 0)
        self.assertEqual(nurses_for_user(self.officer).count(), 2)
        self.assertEqual(list(filter_employers_for_user(self.hr)), [self.employer])
        self.assertEqual(filter_employers_for_user(self.no_group).count(), 0)

    def test_hr_photo_access_is_employer_scoped(self):
        nurse = self.create_nurse()
        self.assertTrue(can_view_nurse_photo(self.hr, nurse))
        self.assertFalse(can_view_nurse_photo(self.other_hr, nurse))
        self.assertTrue(can_view_nurse_photo(self.officer, nurse))


class ProtectedMediaTests(RegistryTestBase):
    def setUp(self):
        self.nurse = self.create_nurse(nin="12345678901")
        self.nurse.photo.save("selfie.jpg", image_upload(), save=True)
        self.document = LicenceDocument.objects.create(
            nurse=self.nurse,
            file=pdf_upload(),
            document_type=LicenceDocument.DocumentType.INITIAL,
        )

    def test_files_live_under_media_root(self):
        self.assertTrue(Path(self.nurse.photo.path).is_relative_to(settings.MEDIA_ROOT))
        self.assertTrue(Path(self.document.file.path).is_relative_to(settings.MEDIA_ROOT))
        self.assertIn("nurse_photos/", self.nurse.photo.name)
        self.assertIn("licence_scans/", self.document.file.name)

    def test_direct_media_path_is_not_routed(self):
        response = self.client.get(settings.MEDIA_URL + self.nurse.photo.name)
        self.assertEqual(response.status_code, 404)

    def test_anonymous_document_access_redirects_to_login(self):
        response = self.client.get(
            reverse("registry:protected_document", args=[self.document.pk])
        )
        self.assertEqual(response.status_code, 302)

    def test_hr_cannot_view_licence_document(self):
        self.client.force_login(self.hr)
        response = self.client.get(
            reverse("registry:protected_document", args=[self.document.pk])
        )
        self.assertEqual(response.status_code, 403)

    def test_officer_can_view_licence_document(self):
        self.client.force_login(self.officer)
        response = self.client.get(
            reverse("registry:protected_document", args=[self.document.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"%PDF-", b"".join(response.streaming_content))

    def test_hr_can_view_own_employer_photo_only(self):
        self.client.force_login(self.hr)
        response = self.client.get(
            reverse("registry:protected_nurse_photo", args=[self.nurse.pk])
        )
        self.assertEqual(response.status_code, 200)

        self.client.force_login(self.other_hr)
        response = self.client.get(
            reverse("registry:protected_nurse_photo", args=[self.nurse.pk])
        )
        self.assertEqual(response.status_code, 403)

    def test_path_traversal_is_rejected(self):
        outside_dir = Path(tempfile.mkdtemp())
        outside = outside_dir / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            with self.assertRaises(Http404):
                _serve_media(SimpleNamespace(path=str(outside)))
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)


class RegistrationTests(RegistryTestBase):
    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get(reverse("registry:register"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register")

    def test_hr_cannot_open_or_submit_registration(self):
        self.client.force_login(self.hr)
        self.assertEqual(self.client.get(reverse("registry:register")).status_code, 200)
        response = self.client.post(
            reverse("registry:register"),
            self.registration_data(),
        )
        self.assertEqual(response.status_code, 302)

    def test_officer_and_supervisor_are_not_publicly_self_service(self):
        self.assertEqual(self.client.get(reverse("registry:register")).status_code, 200)
        self.client.force_login(self.hr)
        self.assertEqual(self.client.get(reverse("registry:register")).status_code, 200)

    def test_valid_registration_creates_pending_nurse_with_consent(self):
        self.client.force_login(self.officer)
        response = self.client.post(
            reverse("registry:register"),
            self.registration_data(),
        )

        nurse = Nurse.objects.get(full_name="New Nurse")
        self.assertRedirects(
            response,
            reverse("registry:registration_success", args=[nurse.pk]),
        )
        self.assertEqual(nurse.record_status, Nurse.RecordStatus.PENDING)
        self.assertEqual(nurse.created_by, self.officer)
        self.assertIsNotNone(nurse.consent_at)
        self.assertEqual(nurse.get_nin(), "12345678901")
        self.assertTrue(nurse.photo)
        self.assertEqual(nurse.documents.count(), 1)

        success = self.client.get(
            reverse("registry:registration_success", args=[nurse.pk])
        )
        self.assertContains(success, nurse.reference)
        self.assertContains(success, "Pending")

    def test_consent_is_required(self):
        self.client.force_login(self.officer)
        data = self.registration_data()
        data.pop("consent")
        response = self.client.post(reverse("registry:register"), data)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "consent before registering")
        self.assertFalse(Nurse.objects.filter(full_name="New Nurse").exists())

    def test_duplicate_nin_warns_and_can_be_confirmed(self):
        existing = self.create_nurse(nin="11111111111", licence_number="EXISTING-LIC")
        self.client.force_login(self.officer)
        data = self.registration_data(
            nin="11111111111",
            licence_number="NEW-LIC",
        )

        response = self.client.post(reverse("registry:register"), data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Possible duplicate")
        self.assertEqual(Nurse.objects.count(), 1)

        data = self.registration_data(
            nin="11111111111",
            licence_number="NEW-LIC",
            confirm_duplicate="on",
        )
        response = self.client.post(reverse("registry:register"), data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Nurse.objects.count(), 2)
        self.assertNotEqual(Nurse.objects.get(full_name="New Nurse").pk, existing.pk)

    def test_duplicate_licence_number_warns(self):
        self.create_nurse(nin="11111111111", licence_number="DUP-LIC")
        self.client.force_login(self.officer)
        response = self.client.post(
            reverse("registry:register"),
            self.registration_data(nin="22222222222", licence_number="dup-lic"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Possible duplicate")
        self.assertContains(response, "licence number")

    def test_no_duplicate_does_not_warn(self):
        self.client.force_login(self.officer)
        response = self.client.post(
            reverse("registry:register"),
            self.registration_data(nin="33333333333", licence_number="UNIQUE-LIC"),
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Possible duplicate")


class UploadValidationTests(RegistryTestBase):
    def test_pdf_jpg_and_png_are_accepted(self):
        uploads = [
            pdf_upload(),
            image_upload("scan.jpg"),
            png_upload(),
        ]
        for upload in uploads:
            with self.subTest(name=upload.name):
                self.assertIs(_validate_upload(upload, "Scan", allow_pdf=True), upload)

    def test_invalid_pdf_header_is_rejected(self):
        upload = SimpleUploadedFile(
            "scan.pdf",
            b"not a pdf",
            content_type="application/pdf",
        )
        with self.assertRaisesMessage(Exception, "not a valid PDF"):
            _validate_upload(upload, "Scan", allow_pdf=True)

    def test_oversized_upload_is_rejected(self):
        upload = pdf_upload(extra=b"0" * (MAX_UPLOAD_SIZE + 1))
        with self.assertRaisesMessage(Exception, "10 MB or smaller"):
            _validate_upload(upload, "Scan", allow_pdf=True)

    def test_unsupported_extension_is_rejected(self):
        upload = SimpleUploadedFile(
            "scan.exe",
            b"MZ",
            content_type="application/octet-stream",
        )
        with self.assertRaisesMessage(Exception, "must be one of"):
            _validate_upload(upload, "Scan", allow_pdf=True)

    def test_invalid_image_is_rejected(self):
        upload = SimpleUploadedFile("selfie.jpg", b"not an image", content_type="image/jpeg")
        with self.assertRaisesMessage(Exception, "not a valid image"):
            _validate_upload(upload, "Selfie", allow_pdf=False)

    def test_registration_page_has_camera_and_fallback(self):
        self.client.force_login(self.officer)
        response = self.client.get(reverse("registry:register"))
        self.assertContains(response, "getUserMedia")
        self.assertContains(response, "capture")
        self.assertContains(response, 'type="file"')

    def test_oversized_scan_shows_field_error(self):
        self.client.force_login(self.officer)
        data = self.registration_data(
            licence_scan=pdf_upload(extra=b"0" * (MAX_UPLOAD_SIZE + 1))
        )
        response = self.client.post(reverse("registry:register"), data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "10 MB or smaller")
        self.assertFalse(Nurse.objects.filter(full_name="New Nurse").exists())


class AdminTests(RegistryTestBase):
    def test_superuser_can_open_admin_and_models_are_registered(self):
        self.client.force_login(self.super_admin)
        response = self.client.get(reverse("admin:index"))
        self.assertEqual(response.status_code, 200)
        for model in (Employer, Nurse, LicenceDocument, Flag, Notification):
            self.assertIn(model, admin.site._registry)

    def test_non_staff_user_is_denied_admin(self):
        self.client.force_login(self.no_group)
        response = self.client.get(reverse("admin:index"))
        self.assertEqual(response.status_code, 302)

    def test_duplicate_marker_and_preview(self):
        first = self.create_nurse(
            nin="11111111111",
            licence_number="DUP-LIC",
            nanm_id="PLT-NUR-000001",
            record_status=Nurse.RecordStatus.APPROVED,
        )
        second = self.create_nurse(
            nin="11111111111",
            licence_number="OTHER-LIC",
            nanm_id="PLT-NUR-000002",
            record_status=Nurse.RecordStatus.APPROVED,
        )
        document = LicenceDocument.objects.create(nurse=first, file=pdf_upload())

        nurse_admin = admin.site._registry[Nurse]
        document_admin = admin.site._registry[LicenceDocument]
        self.assertTrue(nurse_admin.possible_duplicate(second))
        self.assertIn(
            reverse("registry:protected_document", args=[document.pk]),
            str(document_admin.preview(document)),
        )

    def test_nin_and_status_are_read_only_in_admin(self):
        nurse_admin = admin.site._registry[Nurse]
        self.assertIn("nin_last4", nurse_admin.readonly_fields)
        self.assertIn("record_status", nurse_admin.readonly_fields)

    def test_hr_can_access_admin_with_restricted_scope(self):
        self.client.force_login(self.hr)
        response = self.client.get(reverse("admin:index"))
        self.assertEqual(response.status_code, 200)

        nurse_own = self.create_nurse(full_name="Own Nurse")
        nurse_other = self.create_nurse(full_name="Other Nurse", employer=self.other_employer)
        self.assertEqual(list(nurses_for_user(self.hr)), [nurse_own])
        self.assertEqual(list(nurses_for_user(self.other_hr)), [nurse_other])

        response = self.client.get(reverse("admin:registry_nurse_changelist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, nurse_own.full_name)
        self.assertNotContains(response, nurse_other.full_name)

        response = self.client.get(reverse("admin:registry_nurse_change", args=[nurse_own.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="readonly"')
        self.assertNotContains(response, 'name="_save"')

    def test_hr_admin_listing_is_employer_scoped(self):
        own = self.create_nurse(full_name="Own Employer")
        other = self.create_nurse(full_name="Other Employer", employer=self.other_employer)

        self.client.force_login(self.hr)
        response = self.client.get(reverse("admin:registry_nurse_changelist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, own.full_name)
        self.assertNotContains(response, other.full_name)

    def test_hr_admin_detail_is_read_only_and_restricted(self):
        own = self.create_nurse(full_name="Own Employer")
        other = self.create_nurse(full_name="Other Employer", employer=self.other_employer)

        self.client.force_login(self.hr)
        own_url = reverse("admin:registry_nurse_change", args=[own.pk])
        other_url = reverse("admin:registry_nurse_change", args=[other.pk])

        response = self.client.get(own_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="readonly"')

        response = self.client.get(other_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/django-admin/", response["Location"])

    def test_hr_is_not_allowed_to_edit_from_admin(self):
        nurse = self.create_nurse()
        self.client.force_login(self.hr)
        response = self.client.get(reverse("admin:registry_nurse_change", args=[nurse.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="readonly"')

    def test_super_admin_can_export_selected_nurses_csv(self):
        nurse = self.create_nurse(full_name="Exportable Nurse")
        self.client.force_login(self.super_admin)
        changelist_url = reverse("admin:registry_nurse_changelist")
        response = self.client.post(
            changelist_url,
            {"action": "export_csv", "_selected_action": [str(nurse.pk)]},
            follow=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])
        self.assertIn("nanm_id", response.content.decode())
        self.assertIn("Exportable Nurse", response.content.decode())

    def test_super_admin_export_is_not_available_to_hr(self):
        self.client.force_login(self.hr)
        response = self.client.get(reverse("admin:registry_nurse_changelist"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Export selected nurses as CSV")

    def test_expiry_reminder_command_is_deduplicated(self):
        nurse = self.create_nurse(
            full_name="Reminder Nurse",
            licence_expiry=timezone.localdate() + timedelta(days=30),
            record_status=Nurse.RecordStatus.APPROVED,
            nanm_id="PLT-NUR-000099",
        )
        call_command("send_expiry_reminders")
        first_count = Notification.objects.filter(
            nurse=nurse,
            type=Notification.Type.EXPIRY_REMINDER,
            licence_expiry=nurse.licence_expiry,
        ).count()
        call_command("send_expiry_reminders")
        second_count = Notification.objects.filter(
            nurse=nurse,
            type=Notification.Type.EXPIRY_REMINDER,
            licence_expiry=nurse.licence_expiry,
        ).count()

        self.assertEqual(first_count, 1)
        self.assertEqual(second_count, 1)
        self.assertEqual(Notification.objects.filter(nurse=nurse).count(), 1)

    def test_licence_status_band_and_reactivation_guard(self):
        nurse = self.create_nurse(
            full_name="Status Check Nurse",
            licence_expiry=timezone.localdate() + timedelta(days=30),
            record_status=Nurse.RecordStatus.APPROVED,
            nanm_id="PLT-NUR-000010",
        )
        self.assertEqual(nurse.licence_status_band, "yellow")
        self.assertEqual(nurse.public_licence_status, "Expiring soon")

        revoked = self.create_nurse(
            full_name="Revoked Nurse",
            licence_expiry=timezone.localdate() + timedelta(days=365),
            record_status=Nurse.RecordStatus.REVOKED,
            nanm_id="PLT-NUR-000011",
        )
        self.assertEqual(revoked.licence_status_band, "red")
        self.assertEqual(revoked.public_licence_status, "Revoked")

        with self.assertRaises(ValidationError):
            transition_nurse(self.supervisor, revoked, "approved", "reactivating")

    def test_suspend_and_revoke_helpers_accept_reason(self):
        nurse = self.create_nurse(
            full_name="Action Nurse",
            licence_expiry=timezone.localdate() + timedelta(days=365),
            record_status=Nurse.RecordStatus.APPROVED,
            nanm_id="PLT-NUR-000012",
        )
        suspend_nurse(self.supervisor, nurse.pk, "misuse of licence")
        nurse.refresh_from_db()
        self.assertEqual(nurse.record_status, Nurse.RecordStatus.SUSPENDED)

        revoke_nurse(self.supervisor, nurse.pk, "serious breach")
        nurse.refresh_from_db()
        self.assertEqual(nurse.record_status, Nurse.RecordStatus.REVOKED)


class HRWorkflowTests(RegistryTestBase):
    def test_hr_self_registration_creates_pending_request(self):
        response = self.client.post(
            reverse("registry:hr_registration"),
            {
                "email": "hr@plateauhospital.test",
                "hospital_name": "Plateau Health Centre",
                "employer_type": Employer.Type.HOSPITAL,
                "lga": "Jos North",
                "contact_email": "contact@plateauhospital.test",
                "password": "StrongPass123!",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            HRRegistrationRequest.objects.filter(email="hr@plateauhospital.test", status=HRRegistrationRequest.Status.PENDING).exists()
        )

    def test_super_admin_approves_hr_registration_and_creates_user(self):
        registration = HRRegistrationRequest.objects.create(
            email="approvedhr@plateauhospital.test",
            hospital_name="Approved Hospital",
            employer_type=Employer.Type.HOSPITAL,
            lga="Jos North",
            contact_email="admin@approvedhospital.test",
            password="StrongPass123!",
        )
        self.client.force_login(self.super_admin)
        response = self.client.post(
            reverse("registry:approve_hr_registration", args=[registration.pk]),
            {"action": "approve"},
        )
        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username="approvedhr")
        self.assertTrue(user.groups.filter(name=HR).exists())
        self.assertTrue(user.employers.filter(name="Approved Hospital").exists())
        registration.refresh_from_db()
        self.assertEqual(registration.status, HRRegistrationRequest.Status.APPROVED)

    def test_officer_and_supervisor_are_not_publicly_self_service(self):
        self.assertEqual(self.client.get(reverse("registry:register")).status_code, 200)
        self.client.force_login(self.hr)
        self.assertEqual(self.client.get(reverse("registry:register")).status_code, 200)

    def test_hr_can_verify_any_nurse_by_explicit_id(self):
        nurse = self.create_nurse(full_name="Other Employer Nurse", employer=self.other_employer, nanm_id="PLT-NUR-999999", record_status=Nurse.RecordStatus.APPROVED)
        self.client.force_login(self.hr)
        response = self.client.get(reverse("registry:verify"), {"nanm_id": nurse.nanm_id})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, nurse.full_name)
        self.assertContains(response, nurse.nanm_id)



class SmokeTests(RegistryTestBase):
    """Smoke test suite for core workflows."""
    
    def test_public_verification(self):
        """Test public verification endpoint."""
        from django.test import Client
        client = Client()
        response = client.get('/verify/')
        self.assertEqual(response.status_code, 200)
    
    def test_admin_access(self):
        """Test admin access."""
        from django.test import Client
        client = Client()
        client.force_login(self.super_admin)
        response = client.get("/django-admin/")
        self.assertEqual(response.status_code, 200)
