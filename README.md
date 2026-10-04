# LMS End-to-End Software Security

An educational LMS security simulator that models authentication and email
notification workflows using constraints, Kripke state models, and automated
tests.

## Run the project

Install the dependencies listed in `requirement.txt`, then run the test suite:

```powershell
python -m pip install -r requirement.txt
python -m pytest -q
```

Run the Streamlit interface with:

```powershell
streamlit run app.py
```

## Authentication security

The authentication example stores passwords as PBKDF2-HMAC-SHA256 hashes with
independent random salts. It also uses randomly generated session tokens and
expires sessions after the configured lifetime.

This is a learning project with in-memory users and sessions. It is not a
production authentication service; a deployed system also needs persistent
storage, operational controls, monitoring, and security review.
