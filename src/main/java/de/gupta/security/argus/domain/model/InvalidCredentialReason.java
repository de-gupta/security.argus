package de.gupta.security.argus.domain.model;

public enum InvalidCredentialReason implements DescribedReason
{
	MALFORMED("The credential could not be parsed as a supported token."),
	INVALID_SIGNATURE("The credential signature could not be trusted."),
	EXPIRED("The credential is expired."),
	NOT_YET_VALID("The credential is not valid yet."),
	INVALID_ISSUER("The credential issuer is not allowed."),
	INVALID_AUDIENCE("The credential audience is not allowed."),
	MISSING_REQUIRED_CLAIM("The credential is missing a required identity attribute."),
	UNSUPPORTED("The credential uses an unsupported format or algorithm.");

	private final String description;

	InvalidCredentialReason(final String description)
	{
		this.description = description;
	}

	@Override
	public String description()
	{
		return description;
	}
}
