package de.gupta.security.argus.domain.model;

public enum InvalidCredentialReason
{
	MALFORMED,
	INVALID_SIGNATURE,
	EXPIRED,
	NOT_YET_VALID,
	INVALID_ISSUER,
	INVALID_AUDIENCE,
	MISSING_REQUIRED_CLAIM,
	UNSUPPORTED
}
