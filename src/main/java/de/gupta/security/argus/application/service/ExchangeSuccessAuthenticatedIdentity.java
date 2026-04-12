package de.gupta.security.argus.application.service;

import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;
import de.gupta.security.hermes.domain.model.IssuedToken;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public final class ExchangeSuccessAuthenticatedIdentity implements AuthenticatedIdentity
{
	private final IssuedToken token;

	static AuthenticatedIdentity of(final IssuedToken token)
	{
		return new ExchangeSuccessAuthenticatedIdentity(token);
	}

	@Override
	public String subject()
	{
		return token.subject();
	}

	@Override
	public Optional<String> issuer()
	{
		return Optional.of(token.issuer());
	}

	@Override
	public Set<String> audiences()
	{
		return token.audiences();
	}

	@Override
	public Optional<Instant> issuedAt()
	{
		return Optional.of(token.issuedAt());
	}

	@Override
	public Optional<Instant> expiresAt()
	{
		return Optional.of(token.expiresAt());
	}

	@Override
	public Optional<Instant> notBefore()
	{
		return Optional.empty();
	}

	@Override
	public Set<String> roles()
	{
		return token.roles();
	}

	private ExchangeSuccessAuthenticatedIdentity(final IssuedToken token)
	{
		this.token = token;
	}
}
