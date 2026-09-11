"""Local transport, TLS certificate, and response-header boundaries.

The application deliberately keeps HTTP development and HTTPS startup as two
explicit modes.  This module owns the small amount of configuration needed to
make that choice observable and fail closed when HTTPS material is incomplete.
The generated certificate is for local lab use only; it is not a production
trust anchor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import ssl
from typing import Mapping

import click
from flask import current_app, request
from flask.cli import with_appcontext

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


TRANSPORT_MODE_HTTP = "http"
TRANSPORT_MODE_HTTPS = "https"
DEFAULT_TRANSPORT_MODE = TRANSPORT_MODE_HTTP
DEFAULT_SERVER_PORT = 1337
DEFAULT_TLS_DIRECTORY_NAME = "tls"
DEFAULT_TLS_CERTIFICATE_NAME = "dev-cert.pem"
DEFAULT_TLS_KEY_NAME = "dev-key.pem"
DEVELOPMENT_CERTIFICATE_VALIDITY_DAYS = 7
TLS_MINIMUM_VERSION = ssl.TLSVersion.TLSv1_2
HSTS_VALUE = "max-age=31536000"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


class TransportConfigurationError(RuntimeError):
    """Raised when the selected transport cannot be started safely."""


class DevelopmentCertificateError(RuntimeError):
    """Raised when a local development certificate cannot be generated."""


def _first_environment_value(
    environment: Mapping[str, str], names: tuple[str, ...], default: str | None = None
) -> str | None:
    for name in names:
        value = environment.get(name)
        if value is not None and value.strip():
            return value.strip()
    return default


def transport_config_from_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str | None]:
    """Return explicit transport defaults from process environment.

    ``SECUREBOARD_TRANSPORT_MODE`` is the documented seam.  The shorter
    ``SECUREBOARD_TRANSPORT`` and ``*_PATH`` spellings remain accepted as
    compatibility aliases for local scripts, without changing the default
    (plain HTTP development mode).
    """

    environment = os.environ if environment is None else environment
    return {
        "TRANSPORT_MODE": _first_environment_value(
            environment,
            ("SECUREBOARD_TRANSPORT_MODE", "SECUREBOARD_TRANSPORT"),
            DEFAULT_TRANSPORT_MODE,
        ),
        "TLS_CERT_FILE": _first_environment_value(
            environment,
            ("SECUREBOARD_TLS_CERT_FILE", "SECUREBOARD_TLS_CERT_PATH"),
        ),
        "TLS_KEY_FILE": _first_environment_value(
            environment,
            ("SECUREBOARD_TLS_KEY_FILE", "SECUREBOARD_TLS_KEY_PATH"),
        ),
        "PORT": _first_environment_value(
            environment,
            ("SECUREBOARD_PORT",),
            str(DEFAULT_SERVER_PORT),
        ),
    }


def normalize_transport_mode(value: object) -> str:
    """Normalize and validate the explicit ``http``/``https`` mode."""

    if not isinstance(value, str):
        raise TransportConfigurationError(
            "TRANSPORT_MODE must be either 'http' or 'https'."
        )
    mode = value.strip().lower()
    if mode not in {TRANSPORT_MODE_HTTP, TRANSPORT_MODE_HTTPS}:
        raise TransportConfigurationError(
            "TRANSPORT_MODE must be either 'http' or 'https'."
        )
    return mode


def resolve_server_port(value: object) -> int:
    """Convert a configured port to a valid TCP port."""

    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise TransportConfigurationError("PORT must be an integer TCP port.") from exc
    if not 1 <= port <= 65535:
        raise TransportConfigurationError("PORT must be between 1 and 65535.")
    return port


def _configured_path(config: Mapping[str, object], *names: str) -> object:
    for name in names:
        value = config.get(name)
        if value is not None and str(value).strip():
            return value
    return None


def _path_for_tls(value: object, label: str) -> Path:
    if value is None or not str(value).strip():
        raise TransportConfigurationError(
            f"HTTPS mode requires {label} configuration."
        )
    path = Path(value).expanduser()
    if not path.is_file():
        raise TransportConfigurationError(
            f"HTTPS {label} does not point to a readable file: {path}"
        )
    try:
        with path.open("rb"):
            pass
    except OSError as exc:
        raise TransportConfigurationError(
            f"HTTPS {label} is not readable: {path}"
        ) from exc
    return path


def create_ssl_context(cert_path: str | os.PathLike[str], key_path: str | os.PathLike[str]) -> ssl.SSLContext:
    """Load a server TLS context with a TLS 1.2 minimum.

    ``SSLContext.load_cert_chain`` validates that the certificate and private
    key form a matching pair.  Any missing, unreadable, malformed, or
    inconsistent material becomes a startup error rather than an HTTP fallback.
    """

    certificate_path = _path_for_tls(cert_path, "certificate path")
    private_key_path = _path_for_tls(key_path, "private-key path")
    try:
        if certificate_path.resolve() == private_key_path.resolve():
            raise TransportConfigurationError(
                "HTTPS certificate and private-key paths must be different files."
            )
    except OSError as exc:
        raise TransportConfigurationError("HTTPS certificate paths could not be resolved.") from exc

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = TLS_MINIMUM_VERSION
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(
            certfile=str(certificate_path),
            keyfile=str(private_key_path),
        )
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise TransportConfigurationError(
            "HTTPS certificate/private-key material is invalid or inconsistent."
        ) from exc
    return context


def ssl_context_from_config(config: Mapping[str, object]) -> ssl.SSLContext | None:
    """Return a TLS context for HTTPS, or ``None`` for explicit HTTP mode."""

    mode = normalize_transport_mode(config.get("TRANSPORT_MODE", DEFAULT_TRANSPORT_MODE))
    if mode == TRANSPORT_MODE_HTTP:
        return None
    cert_path = _configured_path(config, "TLS_CERT_FILE", "TLS_CERT_PATH")
    key_path = _configured_path(config, "TLS_KEY_FILE", "TLS_KEY_PATH")
    if cert_path is None or key_path is None:
        raise TransportConfigurationError(
            "HTTPS mode requires TLS_CERT_FILE and TLS_KEY_FILE; refusing HTTP fallback."
        )
    return create_ssl_context(cert_path, key_path)


def add_security_headers(response):
    """Apply the central response policy, including HTTPS-only HSTS."""

    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = HSTS_VALUE
    else:
        # A response must never teach a plain-HTTP client to pin an insecure
        # origin, even if a route or test supplied the header itself.
        response.headers.pop("Strict-Transport-Security", None)
    return response


def register_security_headers(app):
    """Register the one central response hook on the application."""

    app.after_request(add_security_headers)


def _default_development_tls_paths() -> tuple[Path, Path]:
    tls_directory = Path(current_app.instance_path) / DEFAULT_TLS_DIRECTORY_NAME
    return (
        tls_directory / DEFAULT_TLS_CERTIFICATE_NAME,
        tls_directory / DEFAULT_TLS_KEY_NAME,
    )


def _restrictive_permissions(path: Path, mode: int) -> None:
    """Best-effort local permissions; Windows ACLs need separate hardening."""

    try:
        os.chmod(path, mode)
    except OSError:
        # The generated key remains usable on platforms whose ACL model does
        # not implement POSIX mode bits.  The limitation is documented for the
        # local Windows lab workflow.
        pass


def generate_development_certificate(
    cert_path: str | os.PathLike[str],
    key_path: str | os.PathLike[str],
    *,
    force: bool = False,
) -> tuple[Path, Path]:
    """Generate a finite-validity self-signed RSA certificate for local labs."""

    certificate_path = Path(cert_path).expanduser()
    private_key_path = Path(key_path).expanduser()
    try:
        if certificate_path.resolve() == private_key_path.resolve():
            raise DevelopmentCertificateError(
                "Certificate and private-key paths must be different files."
            )
    except OSError as exc:
        raise DevelopmentCertificateError(
            "Certificate paths could not be resolved."
        ) from exc
    if certificate_path.exists() or private_key_path.exists():
        if not force:
            raise DevelopmentCertificateError(
                "Certificate or private-key file already exists; use --force to replace it."
            )
    if certificate_path.is_dir() or private_key_path.is_dir():
        raise DevelopmentCertificateError("Certificate and key paths must be files.")

    try:
        certificate_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DevelopmentCertificateError(
            "Could not create the development TLS output directory."
        ) from exc
    _restrictive_permissions(certificate_path.parent, 0o700)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    now = datetime.now(timezone.utc)
    not_valid_before = (now - timedelta(minutes=1)).replace(tzinfo=None)
    not_valid_after = (
        now + timedelta(days=DEVELOPMENT_CERTIFICATE_VALIDITY_DAYS)
    ).replace(tzinfo=None)
    san_names = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    try:
        if force:
            private_key_path.write_bytes(key_bytes)
            certificate_path.write_bytes(certificate_bytes)
        else:
            # Exclusive creation prevents a concurrent invocation from
            # silently replacing a key after the existence check above.
            with private_key_path.open("xb") as key_file:
                key_file.write(key_bytes)
            try:
                with certificate_path.open("xb") as cert_file:
                    cert_file.write(certificate_bytes)
            except Exception:
                try:
                    private_key_path.unlink()
                except OSError:
                    pass
                raise
    except (OSError, ValueError) as exc:
        raise DevelopmentCertificateError(
            "Could not write the development certificate and private key."
        ) from exc

    _restrictive_permissions(private_key_path, 0o600)
    _restrictive_permissions(certificate_path, 0o644)
    return certificate_path, private_key_path


@click.command("generate-dev-tls")
@click.option(
    "--cert",
    "--cert-path",
    "cert_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Certificate output path (default: instance/tls/dev-cert.pem).",
)
@click.option(
    "--key",
    "--key-path",
    "key_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Private-key output path (default: instance/tls/dev-key.pem).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Explicitly replace existing output files.",
)
@with_appcontext
def _generate_dev_tls_command(cert_path: Path | None, key_path: Path | None, force: bool):
    """Generate a self-signed certificate for the local lab only."""

    default_cert, default_key = _default_development_tls_paths()
    try:
        certificate_path, private_key_path = generate_development_certificate(
            cert_path or default_cert,
            key_path or default_key,
            force=force,
        )
    except DevelopmentCertificateError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Development TLS certificate written to {certificate_path}")
    click.echo(f"Development TLS private key written to {private_key_path}")
    click.echo("This self-signed certificate is for local lab use, not production trust.")


def register_transport_cli_commands(app) -> None:
    """Register the explicit local development TLS command."""

    if _generate_dev_tls_command.name not in app.cli.commands:
        app.cli.add_command(_generate_dev_tls_command)
