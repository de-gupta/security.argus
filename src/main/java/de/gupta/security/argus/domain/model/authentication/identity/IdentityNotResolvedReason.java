package de.gupta.security.argus.domain.model.authentication.identity;

import de.gupta.security.argus.domain.description.DescribedReason;

public enum IdentityNotResolvedReason implements DescribedReason
{
	MISSING_EXTERNAL_IDENTITY("The upstream token did not contain the identity attribute required for local resolution."),
	USER_NOT_FOUND("The upstream identity was trusted, but no matching local user could be resolved."),
	MISSING_LOCAL_SUBJECT("A local user was found, but no stable local subject could be produced for authentication.");

	private final String description;

	IdentityNotResolvedReason(final String description)
	{
		this.description = description;
	}

	@Override
	public String description()
	{
		return description;
	}
}