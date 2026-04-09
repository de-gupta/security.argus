package de.gupta.security.argus.api.identity;

import java.util.Optional;

@FunctionalInterface
public interface ExternalIdentityAdapter<ExternalIdentity>
{
	static ExternalIdentityAdapter<String> stringIdentity()
	{
		return Optional::ofNullable;
	}

	Optional<ExternalIdentity> adapt(final String externalIdentity);
}