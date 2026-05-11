# Python — Before and After

## Scenario

A Django application stores patient health records. Certain fields
(SSN, diagnosis, prescriptions) must be encrypted at rest per HIPAA.
Keys must rotate annually and every encrypt/decrypt must be auditable.

---

## Before: Django + `cryptography` library

```python
# models.py
from django.db import models
from cryptography.fernet import Fernet
import os

# One key for everything. Stored in an env var.
# Rotation means generating a new key, re-encrypting every row
# in the database during a maintenance window, and redeploying.
FERNET_KEY = os.environ["DJANGO_ENCRYPTION_KEY"]
fernet = Fernet(FERNET_KEY)


class PatientRecord(models.Model):
    patient_id = models.CharField(max_length=64)
    name = models.CharField(max_length=255)

    # Manual encryption on every field
    _ssn = models.BinaryField(db_column="ssn")
    _diagnosis = models.BinaryField(db_column="diagnosis")
    _prescriptions = models.BinaryField(db_column="prescriptions")

    @property
    def ssn(self):
        return fernet.decrypt(bytes(self._ssn)).decode()

    @ssn.setter
    def ssn(self, value):
        self._ssn = fernet.encrypt(value.encode())

    @property
    def diagnosis(self):
        return fernet.decrypt(bytes(self._diagnosis)).decode()

    @diagnosis.setter
    def diagnosis(self, value):
        self._diagnosis = fernet.encrypt(value.encode())

    @property
    def prescriptions(self):
        return fernet.decrypt(bytes(self._prescriptions)).decode()

    @prescriptions.setter
    def prescriptions(self, value):
        self._prescriptions = fernet.encrypt(value.encode())


# views.py
def create_patient(request):
    record = PatientRecord(
        patient_id="P-12345",
        name="Jane Doe",
    )
    record.ssn = "123-45-6789"
    record.diagnosis = "Type 2 Diabetes"
    record.prescriptions = "Metformin 500mg"
    record.save()
    # No audit log. No key rotation. No per-patient isolation.
    # HIPAA auditor asks "who accessed this patient's data?" — no answer.
```

### Problems

- Fernet is symmetric but has no key hierarchy — one key for all patients
- No audit trail of decrypt operations (HIPAA violation)
- Rotation requires downtime and a data migration script
- Three fields × same boilerplate — error-prone, tedious
- No encryption context — a row's ciphertext can be copied to another row
- Key in env var — leaked key compromises all records

---

## After: Django + `keyrack` Python SDK

```python
# models.py
from django.db import models
from keyrack.django import EncryptedTextField, EncryptedField


class PatientRecord(models.Model):
    patient_id = models.CharField(max_length=64)
    name = models.CharField(max_length=255)

    # Declarative encryption. KeyRack handles everything:
    # - Per-tenant key hierarchy (patient_id used as tenant context)
    # - Encryption context binding (field name + patient_id)
    # - Key versioning in ciphertext header (rotation-safe)
    # - Audit event on every encrypt/decrypt
    ssn = EncryptedTextField(
        context_fields=["patient_id"],
        key_description="patient-ssn-dek",
    )
    diagnosis = EncryptedTextField(
        context_fields=["patient_id"],
        key_description="patient-diagnosis-dek",
    )
    prescriptions = EncryptedTextField(
        context_fields=["patient_id"],
        key_description="patient-prescriptions-dek",
    )


# views.py
def create_patient(request):
    record = PatientRecord(
        patient_id="P-12345",
        name="Jane Doe",
        ssn="123-45-6789",           # encrypted transparently on save
        diagnosis="Type 2 Diabetes",  # each field gets its own DEK
        prescriptions="Metformin 500mg",
    )
    record.save()
    # KeyRack audit log records: who, when, which key, which field, result.
    # HIPAA auditor can query: "show all decrypts of patient P-12345's SSN"


def read_patient(request, patient_id):
    record = PatientRecord.objects.get(patient_id=patient_id)
    ssn = record.ssn  # decrypted transparently, audit event emitted
    # If the encryption context doesn't match (e.g., someone swapped
    # ciphertext between rows), decrypt fails. Data integrity enforced.


# settings.py
KEYRACK = {
    "SERVICE_URL": "http://localhost:8080",
    "AUTH_TOKEN": os.environ.get("KEYRACK_TOKEN"),
    # Or for production:
    # "MTLS_CERT": "/etc/keyrack/client.pem",
    # "MTLS_KEY": "/etc/keyrack/client-key.pem",
}

# management/commands/rotate_keys.py (or a cron job)
#
# from keyrack import KeyRack
# kr = KeyRack.from_django_settings()
# kr.rotate_key("patient-root-kek")
#
# This creates rotation jobs for all dependent DEKs.
# A background worker re-encrypts affected rows using the
# cooperative protocol — no maintenance window needed.
```

### What changed

| Concern | Before | After |
|---------|--------|-------|
| Code per encrypted field | 8 lines (property + setter) | 1 line (`EncryptedTextField`) |
| Key management | Env var, manual | KeyRack service, automatic hierarchy |
| Audit trail | None | Every encrypt/decrypt logged |
| Key rotation | Maintenance window | `rotate_key()` + background worker |
| Per-patient isolation | None | Encryption context binding |
| HIPAA compliance evidence | Manual | Query KeyRack audit log |
| Cross-row data swap attack | Not prevented | Encryption context mismatch → decrypt fails |

---

## Alternative: boto3 path (no new SDK needed)

If the Django app already uses AWS KMS via `boto3`, point it at the
KeyRack AWS KMS shim. Zero code changes:

```python
# settings.py — before
AWS_KMS_ENDPOINT = None  # uses real AWS KMS

# settings.py — after
AWS_KMS_ENDPOINT = "http://keyrack-aws-shim:8080"

# All existing boto3.client('kms') calls now go through KeyRack.
# You get audit, rotation tracking, and crypto agility for free.
```
