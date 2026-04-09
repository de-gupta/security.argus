package de.gupta.security.argus.application.service;

import de.gupta.security.augustus.api.TokenVersionVerifier;
import de.gupta.security.hermes.api.TokenExchangeService;
import de.gupta.security.themis.api.TokenVerifier;

record AuthenticationDependencies(TokenExchangeService tokenExchangeService,
                                  TokenVerifier authenticatedTokenVerifier,
                                  TokenVersionVerifier<String, Long> tokenVersionVerifier)
{
}
