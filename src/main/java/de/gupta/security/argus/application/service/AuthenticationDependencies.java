package de.gupta.security.argus.application.service;

import de.gupta.security.augustus.api.TokenRevocationVerifier;
import de.gupta.security.hermes.api.TokenExchangeService;
import de.gupta.security.themis.api.TokenVerifier;

record AuthenticationDependencies<ExternalIdentity, User>(
		TokenVerifier upstreamTokenVerifier,
		TokenExchangeService tokenExchangeService,
		TokenRevocationVerifier<ExternalIdentity, User> tokenRevocationVerifier)
{
}
