"""Run with: python -m genie_gateway"""

import logging
import sys

import uvicorn

from .app import create_app
from .cli import main as cli_main
from .config import Settings
from .diagnose import log_startup
from .observability import configure_logging


def main() -> None:
    if len(sys.argv) > 1:
        sys.exit(cli_main(sys.argv[1:]))
    settings = Settings.from_env()  # raises on unsafe production config before anything starts
    configure_logging(settings.log_level, json_logs=settings.is_production or settings.log_level != "DEBUG")
    log_startup(settings)
    if settings.jwt_secret == Settings.jwt_secret:
        logging.getLogger("genie_gateway").warning("JWT_SECRET is the demo default; set it before real use")
    # Forwarded headers (X-Forwarded-Proto/For) are trusted only from TRUSTED_PROXY_IPS.
    # Empty means no proxy is trusted, which is correct when uvicorn serves TLS itself.
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        ssl_certfile=settings.tls_cert_file or None,
        ssl_keyfile=settings.tls_key_file or None,
        proxy_headers=bool(settings.trusted_proxy_ips),
        forwarded_allow_ips=settings.trusted_proxy_ips or None,
        access_log=False,  # request ID and audit log carry the useful detail
    )


if __name__ == "__main__":
    main()
