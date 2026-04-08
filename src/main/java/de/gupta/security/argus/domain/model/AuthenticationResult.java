package de.gupta.security.argus.domain.model;

public sealed interface AuthenticationResult permits AuthenticationSuccess, AuthenticationFailure
{
}
