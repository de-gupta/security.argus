package de.gupta.security.argus.domain.model.authentication;

public sealed interface AuthenticationResult permits AuthenticationSuccess, AuthenticationFailure
{
}