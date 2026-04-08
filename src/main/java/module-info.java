module de.gupta.security.argus
{
	exports de.gupta.security.argus.api.authentication;
	exports de.gupta.security.argus.api.identity;
	exports de.gupta.security.argus.api.token;
	exports de.gupta.security.argus.api.trust;
	exports de.gupta.security.argus.domain.description;
	exports de.gupta.security.argus.domain.model.authentication;
	exports de.gupta.security.argus.domain.model.authentication.availability;
	exports de.gupta.security.argus.domain.model.authentication.credential;
	exports de.gupta.security.argus.domain.model.authentication.currentness;
	exports de.gupta.security.argus.domain.model.authentication.identity;
	exports de.gupta.security.argus.domain.model.identity;

	requires jjwt.api;

	requires de.gupta.security.hermes;
	requires de.gupta.security.augustus;
	requires de.gupta.security.themis;

	requires de.gupta.aletheia;
	requires de.gupta.athena;
}