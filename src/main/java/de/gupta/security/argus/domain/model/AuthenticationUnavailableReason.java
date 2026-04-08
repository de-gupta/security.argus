package de.gupta.security.argus.domain.model;

public enum AuthenticationUnavailableReason
{
	TOKEN_ISSUANCE_FAILED,
	INTERNAL_VERIFICATION_FAILED,
	CURRENTNESS_CHECK_FAILED,
	PIPELINE_FAILURE
}
