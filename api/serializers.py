from rest_framework import serializers

from registry.models import Nurse


class PublicNurseSerializer(serializers.ModelSerializer):
    licence_status = serializers.SerializerMethodField()
    photo_url = serializers.SerializerMethodField()
    employer = serializers.SerializerMethodField()

    class Meta:
        model = Nurse
        fields = (
            "nanm_id",
            "full_name",
            "photo_url",
            "licence_status",
            "licence_expiry",
            "employer",
            "record_status",
        )

    def get_licence_status(self, obj):
        return obj.public_licence_status

    def get_photo_url(self, obj):
        if not obj.photo:
            return ""
        request = self.context.get("request")
        if request is not None:
            from django.urls import reverse

            return request.build_absolute_uri(
                reverse("verify_nurse_photo", args=[obj.nanm_id])
            )
        return ""

    def get_employer(self, obj):
        return obj.employer.name if obj.employer else ""


class NurseProfileSerializer(serializers.ModelSerializer):
    licence_status = serializers.CharField(
        source="public_licence_status", read_only=True
    )
    employer = serializers.CharField(source="employer.name", read_only=True)
    employment_confirmed = serializers.SerializerMethodField()
    employment_status = serializers.CharField(read_only=True)
    employment_decided_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Nurse
        fields = (
            "id",
            "nanm_id",
            "full_name",
            "email",
            "phone",
            "photo",
            "licence_number",
            "licence_expiry",
            "licence_status",
            "specialty",
            "cadre",
            "employer",
            "ward",
            "record_status",
            "employer_confirmed_at",
            "employment_confirmed",
            "employment_status",
            "employment_decided_at",
            "created_at",
        )

    def get_employment_confirmed(self, obj):
        return obj.employer_confirmed_at is not None
