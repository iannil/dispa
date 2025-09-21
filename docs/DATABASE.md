Database Setup (SQLite & PostgreSQL)

This project supports SQLite and PostgreSQL. MySQL is intentionally disabled.

Quick Start
- SQLite (file): set DATABASE_URL to sqlite:///absolute/path/to/traffic.db
- SQLite (in‑memory): sqlite::memory:
- PostgreSQL: postgresql://USER:PASSWORD@HOST:5432/DATABASE

Running Migrations via sqlx-cli
1) Install sqlx-cli with only the drivers you need (uses Rustls):

   cargo install sqlx-cli --no-default-features --features rustls,sqlite,postgres

2) Create the database
- SQLite (file DB is created on first connect):

   sqlx database create --database-url "sqlite:///$(pwd)/data/traffic.db"

- PostgreSQL:

   export DATABASE_URL="postgresql://user:password@localhost:5432/dispa"
   sqlx database create

3) Run migrations
- SQLite:

   sqlx migrate run --source migrations/sqlite \
     --database-url "sqlite:///$(pwd)/data/traffic.db"

- PostgreSQL:

   export DATABASE_URL="postgresql://user:password@localhost:5432/dispa"
   sqlx migrate run --source migrations/postgres

Connection Pool Examples
- SQLite (sqlx, Tokio + Rustls runtime):

```rust
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

let pool = SqlitePoolOptions::new()
    .max_connections(5)
    .connect("sqlite:///path/to/traffic.db")
    .await?;
```

- PostgreSQL:

```rust
use sqlx::{PgPool, postgres::PgPoolOptions};

let pool = PgPoolOptions::new()
    .max_connections(10)
    .connect("postgresql://user:password@localhost:5432/dispa")
    .await?;
```

Notes
- The application currently initializes the SQLite schema automatically when using SQLite.
- For PostgreSQL, prefer running the migrations above before starting the app.
- MySQL is not enabled; this avoids pulling the rsa crate flagged by RUSTSEC-2023-0071.

