package de.gupta.security.argus.adapter;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

public interface AuthenticationServiceFacade
{
	AuthenticationResult authenticate(final String token);
}