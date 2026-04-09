package de.gupta.security.argus.domain.model.authentication;

import de.gupta.security.argus.domain.description.Described;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailableReason;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolvedReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("authentication reasons")
@TestInstance(PER_CLASS)
final class AuthenticationReasonDescriptionTest
{
	private record DescriptionCase(String description, Described reason)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	@Nested
	@DisplayName("as described reasons")
	@TestInstance(PER_CLASS)
	final class DescribedReasons
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldExposeNonBlankDescriptions(final DescriptionCase input)
		{
			assertThat(input.reason().description())
					.as(input.description())
					.isNotBlank();
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(
								 Stream.of(InvalidCredentialReason.values())
					                   .map(reason -> new DescriptionCase(
											   "when invalid credential reason " + reason.name() + " is described",
											   reason)),
								 Stream.of(AuthenticationNotCurrentReason.values())
					                   .map(reason -> new DescriptionCase(
											   "when currentness reason " + reason.name() + " is described",
											   reason)),
								 Stream.of(IdentityNotResolvedReason.values())
					                   .map(reason -> new DescriptionCase(
											   "when identity reason " + reason.name() + " is described",
											   reason)),
								 Stream.of(AuthenticationUnavailableReason.values())
					                   .map(reason -> new DescriptionCase(
											   "when availability reason " + reason.name() + " is described",
											   reason)))
			             .flatMap(stream -> stream)
			             .map(Arguments::of);
		}
	}
}