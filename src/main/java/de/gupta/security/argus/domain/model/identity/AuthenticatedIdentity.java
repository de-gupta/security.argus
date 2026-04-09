package de.gupta.security.argus.domain.model.identity;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public sealed interface AuthenticatedIdentity
		permits NormalizedTokenAuthenticatedIdentity
{
	String subject();

	Optional<String> issuer();

	Set<String> audiences();

	Optional<Instant> issuedAt();

	Optional<Instant> expiresAt();

	Optional<Instant> notBefore();

	Set<String> roles();
}