package de.gupta.security.argus.api.authentication;

import de.gupta.security.argus.adapter.AuthenticationServiceFacadeFactory;
import de.gupta.security.argus.application.service.AuthenticationResultMapperFactory;
import de.gupta.security.argus.application.service.AuthenticationServiceFactory;

import java.util.Objects;

public final class AuthenticatorFactory
{
    public static <ExternalIdentity, User> Authenticator create(
            final AuthenticatorConfiguration<ExternalIdentity, User> configuration)
    {
        Objects.requireNonNull(configuration, "configuration must not be null");
        return ConfiguredAuthenticator.create(AuthenticationServiceFacadeFactory.create(
                AuthenticationServiceFactory.create(configuration,
                        AuthenticationResultMapperFactory.create())));
    }

    private AuthenticatorFactory()
    {
    }
}
