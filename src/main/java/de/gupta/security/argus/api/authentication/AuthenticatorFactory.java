package de.gupta.security.argus.api.authentication;

import java.util.Objects;

public final class AuthenticatorFactory
{
    public static <ExternalIdentity, User> Authenticator create(
            final AuthenticatorConfiguration<ExternalIdentity, User> configuration)
    {
        Objects.requireNonNull(configuration, "configuration must not be null");
        throw new UnsupportedOperationException("Authenticator wiring is not implemented yet");
    }

    private AuthenticatorFactory()
    {
    }
}