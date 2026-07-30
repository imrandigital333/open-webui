"""Entry point so the service can start with `python -m app`.

Host, port and TLS are read from the environment, so HTTPS can be turned on
without changing the launch command — just set the two SSL env vars:

    TROUBLESHOOTER_SSL_CERTFILE=/root/.ssl/streamlit/streamlit-bundle.pem
    TROUBLESHOOTER_SSL_KEYFILE=/root/.ssl/streamlit/streamlit.key

When both are set the app serves HTTPS; otherwise it serves plain HTTP (e.g.
behind an nginx/SSO reverse proxy).
"""

import os

import uvicorn


def main() -> None:
    host = os.environ.get("TROUBLESHOOTER_HOST", "0.0.0.0")
    port = int(os.environ.get("TROUBLESHOOTER_PORT", "8090"))
    cert = (os.environ.get("TROUBLESHOOTER_SSL_CERTFILE") or "").strip()
    key = (os.environ.get("TROUBLESHOOTER_SSL_KEYFILE") or "").strip()

    kwargs: dict = {"host": host, "port": port}
    if cert and key:
        kwargs["ssl_certfile"] = cert
        kwargs["ssl_keyfile"] = key
        keypass = os.environ.get("TROUBLESHOOTER_SSL_KEY_PASSWORD")
        if keypass:
            kwargs["ssl_keyfile_password"] = keypass
        print(f"[ai-troubleshooter] serving HTTPS on {host}:{port} (cert: {cert})")
    else:
        print(f"[ai-troubleshooter] serving HTTP on {host}:{port} "
              "(no TLS — set TROUBLESHOOTER_SSL_CERTFILE/KEYFILE to enable HTTPS)")

    uvicorn.run("app.main:app", **kwargs)


if __name__ == "__main__":
    main()
