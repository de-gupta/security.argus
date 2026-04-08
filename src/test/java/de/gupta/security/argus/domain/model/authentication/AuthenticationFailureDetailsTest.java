package de.gupta.security.argus.domain.model.authentication;

import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailableReason;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolvedReason;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

final class AuthenticationFailureDetailsTest
{
	@Test
	void shouldWrapStringDetailsForInvalidCredential()
	{
		assertThat(InvalidCredential.of(InvalidCredentialReason.MALFORMED, "bad token").details())
				.contains(FailureDetails.of("bad token"));
	}

	@Test
	void shouldStoreExplicitFailureDetailsForIdentityNotResolved()
	{
		final FailureDetails failureDetails = FailureDetails.of("user missing");

		assertThat(IdentityNotResolved.of(IdentityNotResolvedReason.USER_NOT_FOUND, failureDetails).details())
				.contains(failureDetails);
	}

	@Test
	void shouldSupportEmptyDetailsForAuthenticationNotCurrent()
	{
		assertThat(AuthenticationNotCurrent.of(AuthenticationNotCurrentReason.VERSION_MISMATCH).details())
				.isEqualTo(Optional.empty());
	}

	@Test
	void shouldWrapStringDetailsForAuthenticationUnavailable()
	{
		assertThat(AuthenticationUnavailable.of(AuthenticationUnavailableReason.SERVICE_UNAVAILABLE,
						"downstream unavailable").details())
				.contains(FailureDetails.of("downstream unavailable"));
	}
}