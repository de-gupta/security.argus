package de.gupta.security.argus.domain.model.authentication;

import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;

public sealed interface AuthenticationFailure extends AuthenticationResult
		permits InvalidCredential, IdentityNotResolved, AuthenticationNotCurrent, AuthenticationUnavailable
{
}