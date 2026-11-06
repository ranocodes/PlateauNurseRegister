# PlateauNurseRegister

Plateau State Nurse Registry and Licence Verification Platform.

## Local setup

```bash
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Put the generated value in NIN_ENCRYPTION_KEY in .env
python manage.py migrate
python manage.py setup_groups
python manage.py seed_demo
python manage.py runserver
```

Open the Vite app at `http://localhost:5173/`. The React staff sign-in is at `/admin/login`; Django administration is available at `/django-admin/`.

`NIN_ENCRYPTION_KEY` is required for registration and NIN reveal. Keep the same key for the life of the database; changing it makes existing encrypted NINs unreadable.

Password recovery is available from the nurse and hospital/HR sign-in pages. Gmail delivery uses `smtp.gmail.com:587` with TLS; set `EMAIL_HOST_USER` to the sending Gmail address and `EMAIL_HOST_PASSWORD` to a Google App Password (not the regular account password). Set `DEFAULT_FROM_EMAIL` to the same address and `FRONTEND_BASE_URL` to the public React app URL. Restart Django after changing these settings. If using another provider, replace the SMTP host and TLS settings with that provider's values.

## Demo data

`seed_demo` creates 60 fake nurses and 4 employers. Use `--reset` to replace existing demo data:

```bash
python manage.py seed_demo --reset
```

## Demo admin credentials

Use the following demo accounts for the local admin dashboard. All share the same password: `DemoPass123!`

### Non-superadmin admins

- `demo_supervisor`
- `demo_hr1`
- `demo_hr2`

### Superadmin

- `demo_superadmin`

### Nurse

- Username: `demo_nurse`
- Password: `DemoPass123!`
- Nurse account email: `demo.nurse@example.test`

Sign in through the React app at `http://localhost:5173/admin/login` for the superadmin or `http://localhost:5173/nurse/login` for the demo nurse. The Django admin site is separate at `http://127.0.0.1:8000/django-admin/`.

## Checks

```bash
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
```


## Production routing

Build the React app in `../plateau-nurse-registry` with `npm run build` and serve its `dist` directory. `deploy/nginx.conf.example` shows a same-origin Nginx setup: React deep links fall back to `index.html`, `/api/v1/` and `/django-admin/` go to Django, and `/media/` is not exposed directly. Registry photos are delivered by the public verification API; uploaded licence documents require an authenticated reviewer.

For production, configure a strong unique `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=False`, `ALLOWED_HOSTS`, `FRONTEND_ORIGINS`, `CSRF_TRUSTED_ORIGINS`, HTTPS, secure cookie flags, and a positive `SECURE_HSTS_SECONDS`. Set `VITE_API_BASE_URL=/api/v1` for same-origin hosting. Use a shared Redis `CACHE_URL` in production so login rate limits work across workers, and set `RATELIMIT_IP_META_KEY=HTTP_X_REAL_IP` only when a trusted reverse proxy overwrites that header (as in the Nginx example). Replace the example hostname, certificate paths, and Django upstream in the Nginx file before deployment.
