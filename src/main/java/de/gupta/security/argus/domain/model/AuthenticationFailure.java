package de.gupta.security.argus.domain.model;

public sealed interface AuthenticationFailure extends AuthenticationResult
		permits InvalidCredential, IdentityNotResolved, AuthenticationNotCurrent, AuthenticationUnavailable
{
}
