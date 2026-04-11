package de.gupta.security.argus.application.service;

import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailableReason;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredentialReason;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrentReason;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolvedReason;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailure;
import de.gupta.security.augustus.domain.model.TokenVersionVerificationFailureReason;
import de.gupta.security.hermes.domain.model.ExchangeFailure;
import de.gupta.security.hermes.domain.model.ExchangeFailureReason;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationFailureReason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("DefaultAuthenticationResultAdapter")
@TestInstance(PER_CLASS)
final class DefaultAuthenticationResultAdapterTest
{
	private final DefaultAuthenticationResultAdapter mapper = new DefaultAuthenticationResultAdapter();

	@FunctionalInterface
	private interface ReasonExtractor
	{
		String apply(AuthenticationResult result);
	}

	@FunctionalInterface
	private interface DetailExtractor
	{
		Optional<String> apply(AuthenticationResult result);
	}

	@FunctionalInterface
	private interface ResultMapping
	{
		AuthenticationResult get();
	}

	private record InvalidCredentialCase(String description,
	                                     VerificationFailure failure,
	                                     InvalidCredentialReason expectedReason,
	                                     Optional<String> expectedDetails)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record ExchangeFailureCase(String description,
	                                   ExchangeFailure failure,
	                                   Class<?> expectedType,
	                                   ReasonExtractor reasonExtractor,
	                                   DetailExtractor detailExtractor,
	                                   String expectedReasonName,
	                                   Optional<String> expectedDetail)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record DirectIdentityCase(String description,
	                                  ResultMapping mapping,
	                                  IdentityNotResolvedReason expectedReason,
	                                  Optional<String> expectedDetail)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record CurrentnessCase(String description,
	                               TokenVersionVerificationFailure<Long> failure,
	                               Class<?> expectedType,
	                               ReasonExtractor reasonExtractor,
	                               DetailExtractor detailExtractor,
	                               String expectedReasonName,
	                               Optional<String> expectedDetail)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	private record AvailabilityCase(String description,
	                                ResultMapping mapping,
	                                AuthenticationUnavailableReason expectedReason,
	                                Optional<String> expectedDetail)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	@Nested
	@DisplayName("as invalid credential mapping")
	@TestInstance(PER_CLASS)
	final class InvalidCredentialMapping
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldMapVerificationFailures(final InvalidCredentialCase input)
		{
			final AuthenticationResult result = mapper.invalidCredential(input.failure());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(InvalidCredential.class);
			assertThat(((InvalidCredential) result).reason())
					.as(input.description())
					.isEqualTo(input.expectedReason());
			assertThat(((InvalidCredential) result).details().map(FailureDetails::message))
					.as(input.description())
					.isEqualTo(input.expectedDetails());
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(
								 new InvalidCredentialCase("when malformed is mapped",
										 new VerificationFailure(VerificationFailureReason.MALFORMED, Optional.empty()),
										 InvalidCredentialReason.MALFORMED,
										 Optional.empty()),
								 new InvalidCredentialCase("when invalid signature is mapped",
										 new VerificationFailure(VerificationFailureReason.INVALID_SIGNATURE, Optional.empty()),
										 InvalidCredentialReason.INVALID_SIGNATURE,
										 Optional.empty()),
								 new InvalidCredentialCase("when expired is mapped with detail",
										 new VerificationFailure(VerificationFailureReason.EXPIRED,
												 Optional.of("expired-at=2026-04-09T12:00:00Z")),
										 InvalidCredentialReason.EXPIRED,
										 Optional.of("expired-at=2026-04-09T12:00:00Z")),
								 new InvalidCredentialCase("when not yet valid is mapped",
										 new VerificationFailure(VerificationFailureReason.NOT_YET_VALID, Optional.empty()),
										 InvalidCredentialReason.NOT_YET_VALID,
										 Optional.empty()),
								 new InvalidCredentialCase("when missing subject becomes missing required claim",
										 new VerificationFailure(VerificationFailureReason.MISSING_SUBJECT, Optional.empty()),
										 InvalidCredentialReason.MISSING_REQUIRED_CLAIM,
										 Optional.empty()),
								 new InvalidCredentialCase("when invalid issuer is mapped",
										 new VerificationFailure(VerificationFailureReason.INVALID_ISSUER, Optional.empty()),
										 InvalidCredentialReason.INVALID_ISSUER,
										 Optional.empty()),
								 new InvalidCredentialCase("when invalid audience is mapped",
										 new VerificationFailure(VerificationFailureReason.INVALID_AUDIENCE, Optional.empty()),
										 InvalidCredentialReason.INVALID_AUDIENCE,
										 Optional.empty()),
								 new InvalidCredentialCase("when unsupported is mapped",
										 new VerificationFailure(VerificationFailureReason.UNSUPPORTED, Optional.empty()),
										 InvalidCredentialReason.UNSUPPORTED,
										 Optional.empty()))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as exchange failure mapping")
	@TestInstance(PER_CLASS)
	final class ExchangeFailureMapping
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldMapHermesFailures(final ExchangeFailureCase input)
		{
			final AuthenticationResult result = mapper.exchangeFailure(input.failure());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(input.expectedType());
			assertThat(input.reasonExtractor().apply(result))
					.as(input.description())
					.isEqualTo(input.expectedReasonName());
			assertThat(input.detailExtractor().apply(result))
					.as(input.description())
					.isEqualTo(input.expectedDetail());
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(
								 new ExchangeFailureCase("when Hermes reports a known upstream verification reason",
										 ExchangeFailure.of(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED,
												 VerificationFailureReason.EXPIRED.name()),
										 InvalidCredential.class,
										 authenticationResult -> ((InvalidCredential) authenticationResult).reason().name(),
										 authenticationResult -> ((InvalidCredential) authenticationResult).details()
										                                                                   .map(FailureDetails::message),
										 InvalidCredentialReason.EXPIRED.name(),
										 Optional.empty()),
								 new ExchangeFailureCase("when Hermes reports an unknown upstream verification reason",
										 ExchangeFailure.of(ExchangeFailureReason.UPSTREAM_VERIFICATION_FAILED, "NOT_A_REASON"),
										 InvalidCredential.class,
										 authenticationResult -> ((InvalidCredential) authenticationResult).reason().name(),
										 authenticationResult -> ((InvalidCredential) authenticationResult).details()
										                                                                   .map(FailureDetails::message),
										 InvalidCredentialReason.UNSUPPORTED.name(),
										 Optional.empty()),
								 new ExchangeFailureCase("when external identity is missing with detail",
										 ExchangeFailure.of(ExchangeFailureReason.MISSING_EXTERNAL_IDENTITY, "email"),
										 IdentityNotResolved.class,
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).reason().name(),
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).details()
										                                                                     .map(FailureDetails::message),
										 IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY.name(),
										 Optional.of("email")),
								 new ExchangeFailureCase("when external identity is missing without detail",
										 ExchangeFailure.of(ExchangeFailureReason.MISSING_EXTERNAL_IDENTITY),
										 IdentityNotResolved.class,
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).reason().name(),
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).details()
										                                                                     .map(FailureDetails::message),
										 IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY.name(),
										 Optional.empty()),
								 new ExchangeFailureCase("when user is not found with detail",
										 ExchangeFailure.of(ExchangeFailureReason.USER_NOT_FOUND, "external-123"),
										 IdentityNotResolved.class,
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).reason().name(),
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).details()
										                                                                     .map(FailureDetails::message),
										 IdentityNotResolvedReason.USER_NOT_FOUND.name(),
										 Optional.of("external-123")),
								 new ExchangeFailureCase("when user is not found without detail",
										 ExchangeFailure.of(ExchangeFailureReason.USER_NOT_FOUND),
										 IdentityNotResolved.class,
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).reason().name(),
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).details()
										                                                                     .map(FailureDetails::message),
										 IdentityNotResolvedReason.USER_NOT_FOUND.name(),
										 Optional.empty()),
								 new ExchangeFailureCase("when local subject is missing",
										 ExchangeFailure.of(ExchangeFailureReason.MISSING_LOCAL_SUBJECT),
										 IdentityNotResolved.class,
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).reason().name(),
										 authenticationResult -> ((IdentityNotResolved) authenticationResult).details()
										                                                                     .map(FailureDetails::message),
										 IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT.name(),
										 Optional.empty()),
								 new ExchangeFailureCase("when issuance fails with details",
										 ExchangeFailure.of(ExchangeFailureReason.ISSUANCE_FAILED, "jwt-encoder-offline"),
										 AuthenticationUnavailable.class,
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).reason().name(),
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).details()
										                                                                           .map(FailureDetails::message),
										 AuthenticationUnavailableReason.SERVICE_UNAVAILABLE.name(),
										 Optional.of("exchange:ISSUANCE_FAILED:jwt-encoder-offline")),
								 new ExchangeFailureCase("when issuance fails without details",
										 ExchangeFailure.of(ExchangeFailureReason.ISSUANCE_FAILED),
										 AuthenticationUnavailable.class,
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).reason().name(),
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).details()
										                                                                           .map(FailureDetails::message),
										 AuthenticationUnavailableReason.SERVICE_UNAVAILABLE.name(),
										 Optional.of("exchange:ISSUANCE_FAILED")))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as direct identity mapping")
	@TestInstance(PER_CLASS)
	final class DirectIdentityMapping
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("cases")
		void shouldMapDirectIdentityFailures(final DirectIdentityCase input)
		{
			final AuthenticationResult result = input.mapping().get();

			assertThat(result)
					.as(input.description())
					.isInstanceOf(IdentityNotResolved.class);
			assertThat(((IdentityNotResolved) result).reason())
					.as(input.description())
					.isEqualTo(input.expectedReason());
			assertThat(((IdentityNotResolved) result).details().map(FailureDetails::message))
					.as(input.description())
					.isEqualTo(input.expectedDetail());
		}

		private Stream<Arguments> cases()
		{
			return Stream.of(
								 new DirectIdentityCase("when missing external identity is mapped directly",
										 () -> mapper.missingExternalIdentity("email"),
										 IdentityNotResolvedReason.MISSING_EXTERNAL_IDENTITY,
										 Optional.of("email")),
								 new DirectIdentityCase("when missing local subject is mapped directly",
										 mapper::missingLocalSubject,
										 IdentityNotResolvedReason.MISSING_LOCAL_SUBJECT,
										 Optional.empty()),
								 new DirectIdentityCase("when user not found is mapped directly",
										 () -> mapper.userNotFound("external-123"),
										 IdentityNotResolvedReason.USER_NOT_FOUND,
										 Optional.of("external-123")))
			             .map(Arguments::of);
		}
	}

	@Nested
	@DisplayName("as currentness and availability mapping")
	@TestInstance(PER_CLASS)
	final class CurrentnessAndAvailabilityMapping
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("currentnessCases")
		void shouldMapCurrentnessFailures(final CurrentnessCase input)
		{
			final AuthenticationResult result = mapper.currentnessFailure(input.failure());

			assertThat(result)
					.as(input.description())
					.isInstanceOf(input.expectedType());
			assertThat(input.reasonExtractor().apply(result))
					.as(input.description())
					.isEqualTo(input.expectedReasonName());
			assertThat(input.detailExtractor().apply(result))
					.as(input.description())
					.isEqualTo(input.expectedDetail());
		}

		@ParameterizedTest(name = "{0}")
		@MethodSource("availabilityCases")
		void shouldMapAvailabilityScenarios(final AvailabilityCase input)
		{
			final AuthenticationResult result = input.mapping().get();

			assertThat(result)
					.as(input.description())
					.isInstanceOf(AuthenticationUnavailable.class);
			assertThat(((AuthenticationUnavailable) result).reason())
					.as(input.description())
					.isEqualTo(input.expectedReason());
			assertThat(((AuthenticationUnavailable) result).details().map(FailureDetails::message))
					.as(input.description())
					.isEqualTo(input.expectedDetail());
		}

		private Stream<Arguments> currentnessCases()
		{
			return Stream.of(
								 new CurrentnessCase("when version mismatch includes details",
										 TokenVersionVerificationFailure.of(
												 TokenVersionVerificationFailureReason.VERSION_MISMATCH,
												 "expected=8, actual=7"),
										 AuthenticationNotCurrent.class,
										 authenticationResult -> ((AuthenticationNotCurrent) authenticationResult).reason().name(),
										 authenticationResult -> ((AuthenticationNotCurrent) authenticationResult).details()
										                                                                          .map(FailureDetails::message),
										 AuthenticationNotCurrentReason.VERSION_MISMATCH.name(),
										 Optional.of("expected=8, actual=7")),
								 new CurrentnessCase("when version mismatch has no details",
										 TokenVersionVerificationFailure.of(
												 TokenVersionVerificationFailureReason.VERSION_MISMATCH),
										 AuthenticationNotCurrent.class,
										 authenticationResult -> ((AuthenticationNotCurrent) authenticationResult).reason().name(),
										 authenticationResult -> ((AuthenticationNotCurrent) authenticationResult).details()
										                                                                          .map(FailureDetails::message),
										 AuthenticationNotCurrentReason.VERSION_MISMATCH.name(),
										 Optional.empty()),
								 new CurrentnessCase("when version lookup fails with details",
										 TokenVersionVerificationFailure.of(
												 TokenVersionVerificationFailureReason.VERSION_LOOKUP_FAILED,
												 "database-timeout"),
										 AuthenticationUnavailable.class,
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).reason().name(),
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).details()
										                                                                           .map(FailureDetails::message),
										 AuthenticationUnavailableReason.IDENTITY_STATE_UNAVAILABLE.name(),
										 Optional.of("database-timeout")),
								 new CurrentnessCase("when version lookup fails without details",
										 TokenVersionVerificationFailure.of(
												 TokenVersionVerificationFailureReason.VERSION_LOOKUP_FAILED),
										 AuthenticationUnavailable.class,
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).reason().name(),
										 authenticationResult -> ((AuthenticationUnavailable) authenticationResult).details()
										                                                                           .map(FailureDetails::message),
										 AuthenticationUnavailableReason.IDENTITY_STATE_UNAVAILABLE.name(),
										 Optional.empty()))
			             .map(Arguments::of);
		}

		private Stream<Arguments> availabilityCases()
		{
			return Stream.of(
								 new AvailabilityCase("when internal token verification fails",
										 () -> mapper.internalCredentialFailure(new VerificationFailure(
												 VerificationFailureReason.INVALID_ISSUER,
												 Optional.of("issuer=wrong"))),
										 AuthenticationUnavailableReason.SERVICE_UNAVAILABLE,
										 Optional.of("internal-token-verification:INVALID_ISSUER:issuer=wrong")),
								 new AvailabilityCase("when version claim is missing",
										 () -> mapper.missingVersionClaim("ver"),
										 AuthenticationUnavailableReason.SERVICE_UNAVAILABLE,
										 Optional.of("Missing internal token version claim: ver")),
								 new AvailabilityCase("when availability is reported directly",
										 () -> mapper.unavailable("service-offline"),
										 AuthenticationUnavailableReason.SERVICE_UNAVAILABLE,
										 Optional.of("service-offline")))
			             .map(Arguments::of);
		}
	}
}