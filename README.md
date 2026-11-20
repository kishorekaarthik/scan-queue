# scan-queue

A distributed file-scanning job queue in Java. Every uploaded file is scanned
and every alert is sent exactly once, even when workers crash at any moment.

> Work in progress: built in phases. This README is expanded at the end with the
> architecture, measured chaos-test results and design decisions.

## Stack

Java 21, Spring Boot 3.5, PostgreSQL 16 (the job table is the queue), Flyway,
MinIO (object storage), YARA CLI, Docker Compose, JUnit 5 + Testcontainers.

## Phase 1: upload and queue

`POST /files` stores the file in MinIO under `uploads/<jobId>` and inserts a
`scan_job` row with `status=QUEUED`, `attempts=0`, `max_attempts=5` and an empty
lease (`lease_owner`, `lease_expires_at`). The object is written **before** the
row, so a worker can never claim a job whose bytes are missing.

| Endpoint | Purpose |
|---|---|
| `POST /files` (multipart `file`) | Upload, returns `201` + `{jobId, status}` |
| `GET /jobs/{id}` | Job row |
| `GET /stats` | Job count per status |

### Run it

```bash
./mvnw package                 # builds the jar and runs the Testcontainers tests
docker compose up -d --build   # postgres, minio, api
bash scripts/smoke-phase1.sh   # uploads a harmless file and the EICAR test string
```

### Safety

No real malware is used anywhere. The "malicious" sample is the
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/),
which antivirus products detect by design and which is harmless.
