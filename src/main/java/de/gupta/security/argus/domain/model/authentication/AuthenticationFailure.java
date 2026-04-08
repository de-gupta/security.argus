package de.gupta.security.argus.domain.model.authentication;

public sealed interface AuthenticationFailure extends AuthenticationResult
		permits InvalidCredential, IdentityNotResolved, AuthenticationNotCurrent, AuthenticationUnavailable
{
}
