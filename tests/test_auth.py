import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from genie_gateway.auth import AuthError, AuthService, build_verifier
from genie_gateway.auth.oidc import OIDCVerifier
from genie_gateway.config import Settings
from genie_gateway.db import Database
from genie_gateway.users import UserService


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


def _oidc(provider, rsa_key, **kwargs):
    verifier = OIDCVerifier(
        provider,
        issuers=kwargs.pop("issuers"),
        jwks_url="https://example.invalid/jwks",
        client_id=kwargs.pop("client_id"),
        **kwargs,
    )
    # Skip the network: hand back our public key for any token.
    verifier._jwks.get_signing_key_from_jwt = lambda token: _FakeSigningKey(rsa_key.public_key())
    return verifier


def _token(rsa_key, **claims):
    base = {"iss": "https://accounts.google.com", "aud": "client-1", "email": "Alice@Example.com",
            "email_verified": True, "name": "Alice", "exp": int(time.time()) + 300}
    base.update(claims)
    return jwt.encode(base, rsa_key, algorithm="RS256")


def _auth(settings):
    db = Database(":memory:")
    users = UserService(db)
    return AuthService(settings, users), users


async def test_local_login_and_token_roundtrip(settings):
    auth, users = _auth(settings)
    from genie_gateway.auth.local import hash_password

    users.create("bob@example.com", provider="local", password_hash=hash_password("s3cret-pass"))
    result = auth.login("bob@example.com", "s3cret-pass")
    assert result["token_type"] == "bearer"
    assert result["must_change_password"] is False
    assert (await auth.authenticate(result["access_token"]))["email"] == "bob@example.com"


def test_local_login_rejects_wrong_password_and_unknown_user(settings):
    auth, users = _auth(settings)
    from genie_gateway.auth.local import hash_password

    users.create("bob@example.com", provider="local", password_hash=hash_password("s3cret-pass"))
    with pytest.raises(AuthError):
        auth.login("bob@example.com", "nope")
    with pytest.raises(AuthError):
        auth.login("ghost@example.com", "s3cret-pass")


async def test_tampered_token_rejected(settings):
    auth, users = _auth(settings)
    from genie_gateway.auth.local import hash_password

    users.create("bob@example.com", provider="local", password_hash=hash_password("s3cret-pass"))
    token = auth.login("bob@example.com", "s3cret-pass")["access_token"]
    with pytest.raises(AuthError):
        await auth.authenticate(token[:-2] + ("aa" if token[-2:] != "aa" else "bb"))


def test_google_token_accepted_and_email_normalised(rsa_key):
    v = _oidc("google", rsa_key, issuers=("https://accounts.google.com",), client_id="client-1")
    p = v.verify(_token(rsa_key))
    assert p.email == "alice@example.com"
    assert p.provider == "google"


def test_google_wrong_audience_or_issuer_rejected(rsa_key):
    v = _oidc("google", rsa_key, issuers=("https://accounts.google.com",), client_id="client-1")
    with pytest.raises(AuthError):
        v.verify(_token(rsa_key, aud="someone-else"))
    with pytest.raises(AuthError):
        v.verify(_token(rsa_key, iss="https://evil.example"))


def test_google_hosted_domain_enforced(rsa_key):
    v = _oidc("google", rsa_key, issuers=("https://accounts.google.com",), client_id="client-1",
              hosted_domain="corp.example")
    with pytest.raises(AuthError):
        v.verify(_token(rsa_key))  # no hd claim
    assert v.verify(_token(rsa_key, hd="corp.example")).email == "alice@example.com"


def test_expired_token_rejected(rsa_key):
    v = _oidc("google", rsa_key, issuers=("https://accounts.google.com",), client_id="client-1")
    with pytest.raises(AuthError):
        v.verify(_token(rsa_key, exp=int(time.time()) - 10))


def test_cognito_access_token_uses_client_id_claim(rsa_key):
    issuer = "https://cognito-idp.eu-west-1.amazonaws.com/pool-1"
    v = _oidc("aws", rsa_key, issuers=(issuer,), client_id="app-1")
    claims = {"iss": issuer, "client_id": "app-1", "email": "alice@example.com", "exp": int(time.time()) + 300,
              "cognito:username": "alice"}  # access tokens carry client_id, not aud
    token = jwt.encode(claims, rsa_key, algorithm="RS256")
    principal = v.verify(token)
    assert principal.provider == "aws"
    assert principal.email == "alice@example.com"


def test_provider_switch_builds_matching_verifier(settings):
    assert build_verifier(settings).provider == "local"
    google = Settings(auth_provider="google", google_client_id="client-1")
    assert build_verifier(google).provider == "google"
    aws = Settings(auth_provider="aws", aws_region="eu-west-1", cognito_user_pool_id="pool-1",
                   cognito_client_id="app-1")
    assert build_verifier(aws).provider == "aws"


def test_password_login_disabled_under_sso(settings):
    sso = Settings(auth_provider="google", google_client_id="client-1", db_path=":memory:")
    auth, _ = _auth(sso)
    with pytest.raises(AuthError):
        auth.login("admin@example.com", "Admin@123")


def test_invalid_provider_and_missing_sso_settings_rejected():
    with pytest.raises(ValueError):
        Settings(auth_provider="okta").validate()
    with pytest.raises(ValueError):
        Settings(auth_provider="google").validate()
    with pytest.raises(ValueError):
        Settings(auth_provider="aws", aws_region="eu-west-1").validate()
