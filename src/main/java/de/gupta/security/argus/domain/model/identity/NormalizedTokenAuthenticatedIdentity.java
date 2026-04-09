package de.gupta.security.argus.domain.model.identity;

import de.gupta.security.themis.domain.model.NormalizedToken;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public final class NormalizedTokenAuthenticatedIdentity implements AuthenticatedIdentity
{
	private final NormalizedToken token;

	public static AuthenticatedIdentity of(final NormalizedToken token)
	{
		return new NormalizedTokenAuthenticatedIdentity(token);
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
	public Optional<Instant> notBefore()
	{
		return token.notBefore();
	}

	@Override
	public Set<String> roles()
	{
		return token.roles();
	}

	private NormalizedTokenAuthenticatedIdentity(NormalizedToken token)
	{
		this.token = token;
	}
}