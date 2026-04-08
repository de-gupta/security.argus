package de.gupta.security.argus.api;

import de.gupta.security.argus.domain.model.TrustedIdentity;

import java.util.Map;

@FunctionalInterface
public interface CustomClaimEnricher<User>
{
	Map<String, ?> enrich(final User user, final TrustedIdentity upstreamIdentity);

	static <User> CustomClaimEnricher<User> none()
	{
		return (_, _) -> Map.of();
	}
}