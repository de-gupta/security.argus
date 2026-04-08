package de.gupta.security.argus.domain.model.authentication.availability;

import de.gupta.security.argus.domain.description.DescribedReason;

public enum AuthenticationUnavailableReason implements DescribedReason
{
	SERVICE_UNAVAILABLE("Authentication could not be completed because the authentication service encountered an internal problem."),
	IDENTITY_STATE_UNAVAILABLE("Authentication could not be completed because current identity state could not be checked.");

	private final String description;

	AuthenticationUnavailableReason(final String description)
	{
		this.description = description;
	}

	@Override
	public String description()
	{
		return description;
	}
}
