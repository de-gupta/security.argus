package de.gupta.security.argus.application.service;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;

public interface AuthenticationService
{
	AuthenticationResult authenticate(final String token);
}