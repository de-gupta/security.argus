package de.gupta.security.argus.domain.model.identity;

import de.gupta.security.themis.domain.model.NormalizedToken;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record NormalizedTokenAuthenticatedIdentity(NormalizedToken token, String roleClaimName)
		implements AuthenticatedIdentity
{
	public static AuthenticatedIdentity of(final NormalizedToken token, final String roleClaimName)
	{
		return new NormalizedTokenAuthenticatedIdentity(token, roleClaimName);
	}

	public NormalizedTokenAuthenticatedIdentity
	{
		Objects.requireNonNull(token, "token must not be null");
		Objects.requireNonNull(roleClaimName, "roleClaimName must not be null");
	}

	@Override
	public String subject()
	{
		return token.subject();
	}

	@Override
	public Optional<String> issuer()
	{
		return token.issuer();
	}

	@Override
	public Set<String> audiences()
	{
		return token.audiences();
	}

	@Override
	public Optional<Instant> issuedAt()
	{
		return token.issuedAt();
	}

	@Override
	public Optional<Instant> expiresAt()
	{
		return token.expiresAt();
	}

	@Override
	public Optional<Instant> validFrom()
	{
		return Optional.empty();
	}

	@Override
	public Set<String> roles()
	{
		return token.stringListClaim(roleClaimName);
	}
}