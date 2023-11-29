# val-stats backend

This FastAPI python project provides a REST API for users to login, sign up or comment on the val-stats web app (https://github.com/Shafin-A/val-stats).

You can check out a live deployed version of the APIs at https://val-stats-server.fly.dev/docs.

# Running locally

You will need a .env file or other way to store two variables SECRET_KEY and DATABASE_URL

You can generate a secret key using:

```
openssl rand -hex 32
```

You will also need a PostgreSQL database url in the form:

```
postgresql://YourUserName:YourPassword@YourHostname:5432/YourDatabaseName
```

Other database providers are untested but might work

### Clone the Repository:

```bash
git clone https://github.com/Shafin-A/val-stats.git
```

### Install Dependencies:

```bash
pip install -r requirements.txt
```

### Run the Application:

```bash
uvicorn main:app --reload
```

### Open in Browser:

Visit http://localhost:8000/docs to explore the API docs to try them yourself
