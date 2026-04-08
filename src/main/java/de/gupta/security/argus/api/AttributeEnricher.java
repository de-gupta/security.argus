package de.gupta.security.argus.api;

import de.gupta.security.argus.domain.model.IdentityAttributes;

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
