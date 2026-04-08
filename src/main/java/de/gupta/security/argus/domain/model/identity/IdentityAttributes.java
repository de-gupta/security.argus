package de.gupta.security.argus.domain.model.identity;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

// TODO: what re things like attribute, attributeValues, numericAttribute doing here?
public interface IdentityAttributes
{
	String subject();

	Optional<String> issuer();

	Set<String> audiences();

	Optional<Instant> issuedAt();

	Optional<Instant> expiresAt();

	Optional<String> attribute(String name);

	Set<String> attributeValues(String name);

	Optional<Long> numericAttribute(String name);
}