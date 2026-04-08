package de.gupta.security.argus.domain.model.authentication.currentness;

import de.gupta.security.argus.domain.description.DescribedReason;

public enum AuthenticationNotCurrentReason implements DescribedReason
{
	VERSION_MISMATCH("The authenticated identity is no longer current because its version is outdated."),
	REVOKED("The authenticated identity is no longer current because it has been revoked."),
	SESSION_NOT_CURRENT("The authenticated identity is no longer current because its session is no longer active.");

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
