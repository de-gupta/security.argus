package de.gupta.security.argus.api.identity;

import java.time.Instant;

@FunctionalInterface
public interface UserRevocationResolver<User>
{
	Instant lastRevokedAt(User user);
}