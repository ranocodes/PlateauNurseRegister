from datetime import timedelta
from io import BytesIO

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone
from PIL import Image
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from registry.models import Employer, HRRegistrationRequest, LicenceDocument, Nurse

User = get_user_model()
TEST_KEY = Fernet.generate_key().decode()


def image_upload():
    buffer = BytesIO()
    Image.new("RGB", (20, 20), "blue").save(buffer, format="JPEG")
    return SimpleUploadedFile("selfie.jpg", buffer.getvalue(), content_type="image/jpeg")


def pdf_upload():
    return SimpleUploadedFile("licence.pdf", b"%PDF-1.4\nregistry test", content_type="application/pdf")


@override_settings(NIN_ENCRYPTION_KEY=TEST_KEY)
class RegistryAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.hr_group, _ = Group.objects.get_or_create(name="HR")
        self.reviewer_group, _ = Group.objects.get_or_create(name="Supervisor")
        self.admin_group, _ = Group.objects.get_or_create(name="Super Admin")
        self.employer = Employer.objects.create(name="Approved Hospital", lga="Jos North", approved=True)
        self.other_employer = Employer.objects.create(name="Other Hospital", lga="Jos South", approved=True)
        self.hr = User.objects.create_user(username="hr", email="hr@example.test", password="password")
        self.hr.groups.add(self.hr_group)
        self.employer.hr_users.add(self.hr)
        self.reviewer = User.objects.create_user(username="reviewer", email="reviewer@example.test", password="password")
        self.reviewer.groups.add(self.reviewer_group)
        self.admin = User.objects.create_user(username="superadmin", email="admin@example.test", password="password")
        self.admin.groups.add(self.admin_group)
        self.nurse_user = User.objects.create_user(username="nurse@example.test", email="nurse@example.test", password="password")
        self.other_nurse_user = User.objects.create_user(username="other@example.test", email="other@example.test", password="password")
        self.nurse = self.make_nurse(self.employer, self.nurse_user)
        self.other_nurse = self.make_nurse(self.other_employer, self.other_nurse_user, "Other Nurse")
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.nurse_user).key}")

    def make_nurse(self, employer, user, name="Test Nurse"):
        nurse = Nurse.objects.create(
            user=user,
            full_name=name,
            phone="08030000001",
            email=user.email,
            licence_number=f"LIC-{user.pk}",
            licence_expiry=timezone.localdate() + timedelta(days=365),
            employer=employer,
            nanm_id=f"PLT-NUR-{user.pk:06d}",
            record_status=Nurse.RecordStatus.APPROVED,
        )
        return nurse

    def test_public_verify_returns_serializer_contract(self):
        response = self.client.get(f"/api/v1/verify/{self.nurse.nanm_id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["full_name"], self.nurse.full_name)
        self.assertEqual(response.data["employer"], self.employer.name)
        self.assertIn("licence_status", response.data)

    @override_settings(FRONTEND_ORIGINS=["http://127.0.0.1:5175"])
    def test_cors_allows_configured_frontend_origin_and_preflight(self):
        response = self.client.options(
            "/api/v1/verify/example/",
            HTTP_ORIGIN="http://127.0.0.1:5175",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response["Access-Control-Allow-Origin"], "http://127.0.0.1:5175")

    def test_nurse_profile_is_scoped_to_authenticated_user(self):
        response = self.client.get("/api/v1/nurse/profile/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], self.nurse.pk)
        self.client.credentials()
        self.assertEqual(self.client.get("/api/v1/nurse/profile/").status_code, 401)

    @override_settings(RATELIMIT_ENABLE=False, EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_password_reset_email_updates_password_and_revokes_tokens(self):
        response = self.client.post("/api/v1/auth/password-reset/", {"email": self.nurse_user.email}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        reset_path = mail.outbox[0].body.split("one-time link:\n", 1)[1].splitlines()[0]
        self.assertIn("/reset-password/", reset_path)
        self.assertTrue(Token.objects.filter(user=self.nurse_user).exists())

        uid_token_path = reset_path.rstrip("/").split("/reset-password/", 1)[1]
        uid, reset_token = uid_token_path.split("/")
        response = self.client.post(
            f"/api/v1/auth/password-reset/{uid}/{reset_token}/",
            {"new_password": "NewSecurePassword!29"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.nurse_user.refresh_from_db()
        self.assertTrue(self.nurse_user.check_password("NewSecurePassword!29"))
        self.assertFalse(Token.objects.filter(user=self.nurse_user).exists())
        self.client.credentials()
        replay = self.client.post(
            f"/api/v1/auth/password-reset/{uid}/{reset_token}/",
            {"new_password": "AnotherSecurePassword!29"},
            format="json",
        )
        self.assertEqual(replay.status_code, 400)

    @override_settings(RATELIMIT_ENABLE=False, EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_password_reset_request_does_not_reveal_unknown_email(self):
        existing = self.client.post("/api/v1/auth/password-reset/", {"email": self.nurse_user.email}, format="json")
        unknown = self.client.post("/api/v1/auth/password-reset/", {"email": "missing@example.test"}, format="json")
        self.assertEqual(existing.status_code, unknown.status_code)
        self.assertEqual(existing.data, unknown.data)
        self.assertEqual(len(mail.outbox), 1)

    def test_hr_directory_only_contains_associated_employer_records(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.hr).key}")
        response = self.client.get("/api/v1/hr/nurses/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["id"] for row in response.data], [self.nurse.pk])

    def test_hr_can_confirm_only_own_employer_nurse(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.hr).key}")
        own = self.client.post(f"/api/v1/hr/nurses/{self.nurse.pk}/confirm/")
        outside = self.client.post(f"/api/v1/hr/nurses/{self.other_nurse.pk}/confirm/")
        self.assertEqual(own.status_code, 200)
        self.assertEqual(outside.status_code, 404)
        self.nurse.refresh_from_db()
        self.assertEqual(self.nurse.employer_confirmed_by, self.hr)
    
    def test_hr_can_reject_only_own_employer_nurse(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.hr).key}"
        )

        original_record_status = self.nurse.record_status
        original_licence_expiry = self.nurse.licence_expiry

        own = self.client.post(
            f"/api/v1/hr/nurses/{self.nurse.pk}/reject/"
        )
        outside = self.client.post(
            f"/api/v1/hr/nurses/{self.other_nurse.pk}/reject/"
        )

        self.assertEqual(own.status_code, 200)
        self.assertEqual(outside.status_code, 404)

        self.nurse.refresh_from_db()

        self.assertEqual(
            self.nurse.employment_status,
            Nurse.EmploymentStatus.REJECTED,
        )
        self.assertIsNotNone(self.nurse.employment_decided_at)
        self.assertEqual(self.nurse.employment_decided_by, self.hr)

        # Employment rejection must not affect registration or licence data.
        self.assertEqual(self.nurse.record_status, original_record_status)
        self.assertEqual(self.nurse.licence_expiry, original_licence_expiry)

        # Rejected employment must not be recorded as a confirmation.
        self.assertIsNone(self.nurse.employer_confirmed_at)
        self.assertIsNone(self.nurse.employer_confirmed_by)

    def test_hr_cannot_decide_employment_twice(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.hr).key}"
        )

        first = self.client.post(
            f"/api/v1/hr/nurses/{self.nurse.pk}/reject/"
        )
        second = self.client.post(
            f"/api/v1/hr/nurses/{self.nurse.pk}/confirm/"
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)

        self.nurse.refresh_from_db()
        self.assertEqual(
            self.nurse.employment_status,
            Nurse.EmploymentStatus.REJECTED,
        )

    def test_renewal_stays_pending_until_reviewer_approves(self):
        old_expiry = self.nurse.licence_expiry
        new_expiry = (timezone.localdate() + timedelta(days=730)).isoformat()
        response = self.client.post(
            "/api/v1/nurse/renew/",
            {"licence_expiry": new_expiry, "file": pdf_upload()},
            format="multipart",
        )
        self.assertEqual(response.status_code, 201)
        document = LicenceDocument.objects.get(pk=response.data["id"])
        self.assertEqual(document.decision, LicenceDocument.Decision.PENDING)
        self.nurse.refresh_from_db()
        self.assertEqual(self.nurse.licence_expiry, old_expiry)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.reviewer).key}")
        queue = self.client.get("/api/v1/admin/renewals/")
        self.assertEqual(queue.status_code, 200)
        result = self.client.post(f"/api/v1/admin/renewals/{document.pk}/", {"action": "approve"})
        self.assertEqual(result.status_code, 200)
        self.nurse.refresh_from_db()
        self.assertEqual(self.nurse.licence_expiry.isoformat(), new_expiry)

    def test_hr_registration_password_is_hashed_and_review_activates_account(self):
        payload = {
            "email": "hospital.hr@example.test", "hospital_name": "New Hospital",
            "employer_type": "hospital", "lga": "Jos East", "contact_email": "contact@example.test",
            "password": "StrongPass123!",
        }
        response = self.client.post("/api/v1/hr/register/", payload, format="json")
        self.assertEqual(response.status_code, 201)
        application = HRRegistrationRequest.objects.get(pk=response.data["id"])
        self.assertNotEqual(application.password, payload["password"])

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.admin).key}")
        queue = self.client.get("/api/v1/admin/hr-registrations/")
        self.assertEqual(queue.status_code, 200)
        result = self.client.post(f"/api/v1/admin/hr-registrations/{application.pk}/", {"action": "approve"})
        self.assertEqual(result.status_code, 200)
        hr_user = User.objects.get(email=payload["email"])
        self.assertTrue(hr_user.check_password(payload["password"]))
        self.assertTrue(hr_user.groups.filter(name="HR").exists())
        login = self.client.post("/api/v1/auth/token/", {
            "email": payload["email"], "password": payload["password"],
        }, format="json")
        self.assertEqual(login.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {login.data['token']}")
        self.assertEqual(self.client.get("/api/v1/me/").data["role"], "hr")

    def test_admin_dashboard_summary_is_super_admin_only_and_live(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.admin).key}")
        response = self.client.get("/api/v1/admin/summary/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["total_nurses"], 2)
        self.assertEqual(response.data["active_licences"], 2)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.hr).key}")
        self.assertEqual(self.client.get("/api/v1/admin/summary/").status_code, 403)

    def test_nurse_registration_creates_pending_record_and_token(self):
        payload = {
            "full_name": "New Nurse", "email": "new.nurse@example.test", "phone": "+2348030000002",
            "nin": "12345678901", "licence_number": "NMCN-NEW-1",
            "licence_expiry": (timezone.localdate() + timedelta(days=500)).isoformat(),
            "specialty": "General", "cadre": "Registered Nurse", "employer": str(self.employer.pk),
            "ward": "Medical", "consent": "true", "password": "StrongPass123!",
        }
        response = self.client.post(
            "/api/v1/register/", {**payload, "licence_scan": pdf_upload(), "selfie": image_upload()},
            format="multipart",
        )
        self.assertEqual(response.status_code, 201, response.data)
        nurse = Nurse.objects.get(email=payload["email"])
        self.assertEqual(nurse.record_status, Nurse.RecordStatus.PENDING)
        self.assertEqual(nurse.user.email, payload["email"])
        self.assertTrue(Token.objects.filter(user=nurse.user).exists())
        self.assertEqual(nurse.documents.get().document_type, LicenceDocument.DocumentType.INITIAL)
        login = self.client.post("/api/v1/auth/token/", {
            "email": payload["email"], "password": payload["password"],
        }, format="json")
        self.assertEqual(login.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {login.data['token']}")
        self.assertEqual(self.client.get("/api/v1/me/").data["role"], "nurse")

    def test_super_admin_login_returns_super_admin_role(self):
        login = self.client.post("/api/v1/auth/token/", {
            "email": self.admin.email, "password": "password",
        }, format="json")
        self.assertEqual(login.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {login.data['token']}")
        self.assertEqual(self.client.get("/api/v1/me/").data["role"], "super_admin")

    def test_super_admin_can_log_in_with_username_identifier(self):
        login = self.client.post("/api/v1/auth/token/", {
            "identifier": self.admin.username, "password": "password",
        }, format="json")
        self.assertEqual(login.status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {login.data['token']}")
        self.assertEqual(self.client.get("/api/v1/me/").data["role"], "super_admin")

    def test_staff_can_search_nurse_records_and_supervisor_cannot_edit_them(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.reviewer).key}")
        response = self.client.get("/api/v1/admin/nurses/", {"search": "Test Nurse"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["id"] for row in response.data], [self.nurse.pk])
        self.assertEqual(response.data[0]["documents"], [])
        self.assertEqual(self.client.patch(f"/api/v1/admin/nurses/{self.nurse.pk}/", {"phone": "08039999999"}).status_code, 403)

    def test_super_admin_can_correct_nurse_profile_and_nin(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.admin).key}")
        response = self.client.patch(
            f"/api/v1/admin/nurses/{self.nurse.pk}/",
            {"phone": "08039999999", "nin": "12345678901", "employer": self.other_employer.pk},
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.nurse.refresh_from_db()
        self.assertEqual(self.nurse.phone, "08039999999")
        self.assertEqual(self.nurse.employer, self.other_employer)
        self.assertEqual(self.nurse.nin_last4, "8901")
        self.assertEqual(self.nurse.get_nin(), "12345678901")

    def test_supervisor_can_review_hr_registration(self):
        application = HRRegistrationRequest.objects.create(
            email="reviewed.hr@example.test", hospital_name="Reviewed Hospital",
            employer_type="hospital", lga="Jos North", password="StrongPass123!",
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.reviewer).key}")
        response = self.client.get("/api/v1/admin/hr-registrations/")
        self.assertEqual(response.status_code, 200)
        decision = self.client.post(f"/api/v1/admin/hr-registrations/{application.pk}/", {"action": "approve"})
        self.assertEqual(decision.status_code, 200, decision.data)

    def test_super_admin_can_create_supervisor_but_hr_cannot(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.hr).key}")
        denied = self.client.post("/api/v1/admin/supervisors/", {
            "email": "new.supervisor@example.test", "password": "LongTemporaryPassword123!",
        })
        self.assertEqual(denied.status_code, 403)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.admin).key}")
        created = self.client.post("/api/v1/admin/supervisors/", {
            "email": "new.supervisor@example.test", "first_name": "Review", "last_name": "Staff",
            "password": "LongTemporaryPassword123!",
        })
        self.assertEqual(created.status_code, 201, created.data)
        user = User.objects.get(email="new.supervisor@example.test")
        self.assertTrue(user.groups.filter(name="Supervisor").exists())
        edit = self.client.patch(f"/api/v1/admin/supervisors/{user.pk}/", {"is_active": "false"}, format="json")
        self.assertEqual(edit.status_code, 200, edit.data)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(self.client.delete(f"/api/v1/admin/supervisors/{user.pk}/").status_code, 204)

    def test_super_admin_can_create_edit_and_delete_nurse_account(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.admin).key}")
        payload = {
            "email": "created.nurse@example.test", "password": "LongTemporaryPassword123!",
            "full_name": "Created Nurse", "phone": "08030000004", "licence_number": "NMCN-CREATED-4",
            "licence_expiry": (timezone.localdate() + timedelta(days=400)).isoformat(),
            "employer": self.employer.pk,
        }
        created = self.client.post("/api/v1/admin/nurses/", payload, format="json")
        self.assertEqual(created.status_code, 201, created.data)
        nurse = Nurse.objects.get(pk=created.data["id"])
        self.assertEqual(nurse.record_status, Nurse.RecordStatus.PENDING)
        self.assertTrue(nurse.user.check_password(payload["password"]))
        edited = self.client.patch(f"/api/v1/admin/nurses/{nurse.pk}/", {"ward": "Surgical"})
        self.assertEqual(edited.status_code, 200, edited.data)
        self.assertEqual(edited.data["ward"], "Surgical")
        self.assertEqual(self.client.delete(f"/api/v1/admin/nurses/{nurse.pk}/").status_code, 204)
        self.assertFalse(User.objects.filter(email=payload["email"]).exists())

    def test_super_admin_can_create_edit_and_delete_hospital_hr_account(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.create(user=self.admin).key}")
        payload = {
            "email": "created.hr@example.test", "password": "LongTemporaryPassword123!",
            "first_name": "Hospital", "last_name": "Staff",
            "employer": {"name": "Created Hospital", "lga": "Jos East", "type": "hospital", "approved": True},
        }
        created = self.client.post("/api/v1/admin/hr-users/", payload, format="json")
        self.assertEqual(created.status_code, 201, created.data)
        user = User.objects.get(email=payload["email"])
        self.assertTrue(user.groups.filter(name="HR").exists())
        edited = self.client.patch(f"/api/v1/admin/hr-users/{user.pk}/", {"is_active": "false"}, format="json")
        self.assertEqual(edited.status_code, 200, edited.data)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(self.client.delete(f"/api/v1/admin/hr-users/{user.pk}/").status_code, 204)
        self.assertFalse(User.objects.filter(pk=user.pk).exists())
