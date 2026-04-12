package de.gupta.security.argus.domain.model.authentication.currentness;

import de.gupta.security.argus.domain.description.Described;

public enum AuthenticationNotCurrentReason implements Described
{
	REVOKED("The upstream token was issued before the last revocation event for this identity.");

	private final String description;

	AuthenticationNotCurrentReason(final String description)
	{
		this.description = description;
	}

	@Override
	public String description()
	{
		return description;
	}
}
