import regex
import json

from urllib.parse import urlencode, urlparse
from authlib.jose import JsonWebKey
from flask import Blueprint, flash, request, redirect

from .identity import is_valid_handle, is_valid_did, resolve_identity, pds_endpoint
from .oauth import resolve_pds_authserver, fetch_authserver_meta, send_par_auth_request
from .security import is_safe_url


def set_up_web_key(app):
	global CLIENT_SECRET_JWK
	# This is a "confidential" OAuth client, meaning it has access to a persistent secret signing key. parse that key as a global.
	CLIENT_SECRET_JWK = JsonWebKey.import_key(app.config["CLIENT_SECRET_JWK"])

	# Defensively check that the public JWK is really public and didn't somehow end up with secret cryptographic key info
	CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
	assert "d" not in CLIENT_PUB_JWK

# OAuth scopes requested by this app (goes in the client metadata, and authorization requests)
OAUTH_SCOPE = "atproto repo:app.bsky.feed.post?action=create"


atmos_blueprint = Blueprint("atmos", __name__)

# Starts the OAuth authorization flow (POST).
@atmos_blueprint.route("/login", methods=("GET", "POST"))
def oauth_login():
	if request.method != "POST":
		return "<h1>Hello Matthew</h1>"

	# Login can start with a handle, DID, or auth server URL. We are calling whatever the user supplied the "username".
	username = request.form["username"]

	# strip unicode control/formatting codepoints (common in copy-pasted handles)
	username = regex.sub(r"[\p{C}]", "", username)

	# strip @ prefix, if present
	if is_valid_handle(username.removeprefix("@")):
		username = username.removeprefix("@")

	if is_valid_handle(username) or is_valid_did(username):
		# If starting with an account identifier, resolve the identity (bi-directionally), fetch the PDS URL, and resolve to the Authorization Server URL
		login_hint = username

		try:
			did, handle, did_doc = resolve_identity(username)
		except Exception as e:
			flash(f"Failed to resolve identity: {e}", "error")
			return "Error: Failed to resolve identity"

		pds_url = pds_endpoint(did_doc)
		print(f"account PDS: {pds_url}")
		auth_server_url = resolve_pds_authserver(pds_url)
		
	elif username.startswith("https://") and is_safe_url(username):
		# When starting with an auth server, we don't know about the account yet.
		did, handle, pds_url = None, None, None
		login_hint = None
		# Check if this is a Resource Server (PDS) URL; otherwise assume it is authorization server
		initial_url = username
		try:
			auth_server_url = resolve_pds_authserver(initial_url)
		except Exception:
			# If initial_url is an AS url, strip any trailing slashes
			auth_server_url = initial_url.rstrip("/")
	else:
		flash("Not a valid handle, DID, or auth server URL", "error")
		return "Error: Not a valid handle, DID, or auth server URL"

	# Fetch Auth Server metadata. For a self-hosted PDS, this will be the same server (the PDS). For large-scale PDS hosts like Bluesky, this may be a separate "entryway" server filling the Auth Server role.
	# IMPORTANT: Authorization Server URL is untrusted input, SSRF mitigations are needed
	print(f"account Authorization Server: {auth_server_url}")
	assert is_safe_url(auth_server_url)
	try:
		authserver_meta = fetch_authserver_meta(auth_server_url)
	except Exception as err:
		print(f"failed to fetch auth server metadata: {err}")
		# raise err
		flash("Failed to fetch Auth Server (Entryway) OAuth metadata", "error")
		return "Error: Failed to fetch Auth Server (Entryway) OAuth metadata"

	# Generate DPoP private signing key for this account session. In theory this could be defered until the token request at the end of the athentication flow, but doing it now allows early binding during the PAR request.
	dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

	# Dynamically compute our "client_id" based on the request HTTP Host
	client_id, redirect_uri = compute_client_id(request.url_root)

	# Submit OAuth Pushed Authentication Request (PAR). We could have constructed a more complex authentication request URL below instead, but there are some advantages with PAR, including failing fast, early DPoP binding, and no URL length limitations.
	pkce_verifier, state, dpop_authserver_nonce, resp = send_par_auth_request(
		auth_server_url,
		authserver_meta,
		login_hint,
		client_id,
		redirect_uri,
		OAUTH_SCOPE,
		CLIENT_SECRET_JWK,
		dpop_private_jwk,
	)
	if resp.status_code == 400:
		print(f"PAR HTTP 400: {resp.json()}")
	resp.raise_for_status()
	# This field is confusingly named: it is basically a token to refering back to the successful PAR request.
	par_request_uri = resp.json()["request_uri"]

	print(f"SHOULD BE saving oauth_auth_request to DB  state={state}")
	# query_db(
	# 	"INSERT INTO oauth_auth_request (state, authserver_iss, did, handle, pds_url, pkce_verifier, scope, dpop_authserver_nonce, dpop_private_jwk) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);",
	# 	[
	# 		state,
	# 		authserver_meta["issuer"],
	# 		did,  # might be None
	# 		handle,  # might be None
	# 		pds_url,  # might be None
	# 		pkce_verifier,
	# 		OAUTH_SCOPE,
	# 		dpop_authserver_nonce,
	# 		dpop_private_jwk.as_json(is_private=True),
	# 	],
	# )

	# Forward the user to the Authorization Server to complete the browser auth flow.
	# IMPORTANT: Authorization endpoint URL is untrusted input, security mitigations are needed before redirecting user
	auth_url = authserver_meta["authorization_endpoint"]
	assert is_safe_url(auth_url)
	qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
	return redirect(f"{auth_url}?{qparam}")


# Dynamically compute our "client_id" based on the request HTTP Host
def compute_client_id(url_root):
	parsed_url = urlparse(url_root)
	if parsed_url.hostname in ["localhost", "127.0.0.1"]:
		# for localhost testing, see https://atproto.com/specs/oauth#localhost-client-development
		redirect_uri = f"http://127.0.0.1:{parsed_url.port}/oauth/callback"
		client_id = "http://localhost?" + urlencode({
			"redirect_uri": redirect_uri,
			"scope": OAUTH_SCOPE,
		})
	else:
		app_url = url_root.replace("http://", "https://")
		redirect_uri = f"{app_url}oauth/callback"
		client_id = f"{app_url}oauth-client-metadata.json"

	return client_id, redirect_uri