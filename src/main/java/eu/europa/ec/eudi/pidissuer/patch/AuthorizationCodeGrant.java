/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * Modified by AUTHADA GmbH
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.pidissuer.patch;


import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;


/**
 * Authorisation code grant. Used in access token requests with an
 * authorisation code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.1.3.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
@Immutable
public class AuthorizationCodeGrant extends AuthorizationGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.AUTHORIZATION_CODE;


	/**
	 * The authorisation code received from the authorisation server.
	 */
	private final AuthorizationCode code;


	/**
	 * The conditionally required redirection URI in the initial
	 * authorisation request.
	 */
	private final URI redirectURI;


	/**
	 * The optional authorisation code verifier for PKCE.
	 */
	private final CodeVerifier codeVerifier;


	/**
	 * Creates a new authorisation code grant.
	 *
	 * @param code        The authorisation code. Must not be {@code null}.
	 * @param redirectURI The redirection URI of the original authorisation
	 *                    request. Required if the {redirect_uri}
	 *                    parameter was included in the authorisation
	 *                    request, else {@code null}.
	 */
	public AuthorizationCodeGrant(final AuthorizationCode code,
                                  final URI redirectURI) {

		this(code, redirectURI, null);
	}


	/**
	 * Creates a new authorisation code grant.
	 *
	 * @param code         The authorisation code. Must not be {@code null}.
	 * @param redirectURI  The redirection URI of the original
	 *                     authorisation request. Required if the
	 *                     {redirect_uri} parameter was included in the
	 *                     authorisation request, else {@code null}.
	 * @param codeVerifier The authorisation code verifier for PKCE,
	 *                     {@code null} if not specified.
	 */
	public AuthorizationCodeGrant(final AuthorizationCode code,
                                  final URI redirectURI,
                                  final CodeVerifier codeVerifier) {

		super(GRANT_TYPE);

		if (code == null)
			throw new IllegalArgumentException("The authorisation code must not be null");

		this.code = code;

		this.redirectURI = redirectURI;

		this.codeVerifier = codeVerifier;
	}


	/**
	 * Gets the authorisation code.
	 *
	 * @return The authorisation code.
	 */
	public AuthorizationCode getAuthorizationCode() {

		return code;
	}


	/**
	 * Gets the redirection URI of the original authorisation request.
	 *
	 * @return The redirection URI, {@code null} if the
	 *         {@code redirect_uri} parameter was not included in the
	 *         original authorisation request.
	 */
	public URI getRedirectionURI() {

		return redirectURI;
	}


	/**
	 * Gets the authorisation code verifier for PKCE.
	 *
	 * @return The authorisation code verifier, {@code null} if not
	 *         specified.
	 */
	public CodeVerifier getCodeVerifier() {

		return codeVerifier;
	}


	@Override
	public Map<String,List<String>> toParameters() {

		Map<String,List<String>> params = new LinkedHashMap<>();
		params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
		params.put("code", Collections.singletonList(code.getValue()));

		if (redirectURI != null)
			params.put("redirect_uri", Collections.singletonList(redirectURI.toString()));

		if (codeVerifier != null)
			params.put("code_verifier", Collections.singletonList(codeVerifier.getValue()));

		return params;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof AuthorizationCodeGrant)) return false;
		AuthorizationCodeGrant that = (AuthorizationCodeGrant) o;
		return code.equals(that.code) && Objects.equals(redirectURI, that.redirectURI) && Objects.equals(getCodeVerifier(), that.getCodeVerifier());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(code, redirectURI, getCodeVerifier());
	}
	
	
	/**
	 * Parses an authorisation code grant from the specified request body
	 * parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=authorization_code
	 * code=SplxlOBeZQQYbYS6WxSbIA
	 * redirect_uri=https://Fclient.example.com/cb
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The authorisation code grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static AuthorizationCodeGrant parse(final Map<String,List<String>> params)
		throws ParseException {
		
		GrantType.ensure(GRANT_TYPE, params);

		// Parse authorisation code
		String codeString = MultivaluedMapUtils.getFirstValue(params, "code");

		if (codeString == null || codeString.trim().isEmpty()) {
			String msg = "Missing or empty code parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		AuthorizationCode code = new AuthorizationCode(codeString);

		// Parse optional redirection URI
		String redirectURIString = MultivaluedMapUtils.getFirstValue(params, "redirect_uri");

		URI redirectURI = null;

		if (redirectURIString != null) {
			try {
				redirectURI = new URI(redirectURIString);
			} catch (URISyntaxException e) {
				String msg = "Invalid redirect_uri parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg), e);
			}
		}


		// Parse optional code verifier
		String codeVerifierString = MultivaluedMapUtils.getFirstValue(params,"code_verifier");

		CodeVerifier codeVerifier = null;

		if (StringUtils.isNotBlank(codeVerifierString)) {

			try {
				codeVerifier = new CodeVerifier(codeVerifierString);
			} catch (IllegalArgumentException e) {
				// Illegal code verifier
				String msg = "Illegal code verifier: " + e.getMessage();
				throw new ParseException(e.getMessage(), OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg), e);
			}
		}

		return new AuthorizationCodeGrant(code, redirectURI, codeVerifier);
	}
}
