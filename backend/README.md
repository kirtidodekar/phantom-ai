# Sentinel AI backend

## Database configuration

The backend uses `app/sentinel.db` as a local SQLite fallback when `DATABASE_URL` is unset or empty. For PostgreSQL, copy `.env.example` to `.env` and provide a PostgreSQL connection URL. Keep `.env` local; it is ignored by Git.

PostgreSQL connections must require TLS by including `sslmode=require` (or a stricter verification mode). Reserved characters in credentials must be URL-encoded. Tables are isolated from provider-managed public tables in a dedicated schema configured by `DATABASE_SCHEMA`, which defaults to `sentinel_ai`. Startup only creates the schema and missing tables; it does not drop or truncate data.

Example configuration (placeholders only):

```dotenv
DATABASE_URL=postgresql://<user>:<url-encoded-password>@<host>:5432/<database>?sslmode=require
DATABASE_SCHEMA=sentinel_ai
```

Install and start from the `backend` directory:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
