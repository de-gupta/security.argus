package de.gupta.security.argus.api.identity;

import de.gupta.security.argus.domain.model.identity.IdentityAttributes;

import java.util.Map;

@FunctionalInterface
public interface AttributeEnricher<User>
{
	Map<String, ?> enrich(final User user, final IdentityAttributes upstreamIdentity);

	static <User> AttributeEnricher<User> none()
	{
		return (_, _) -> Map.of();
	}
}
