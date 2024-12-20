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


import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;

import java.util.List;
import java.util.Map;


/**
 * Authorisation grant. Extending classes should be immutable.
 *
 * <p>Supported authorisation grant types:
 *
 * <ul>
 *     <li>{@link GrantType#AUTHORIZATION_CODE Authorisation code}
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.3.
 * </ul>
 */
public abstract class AuthorizationGrant {


	/**
	 * The authorisation grant type.
	 */
	private final GrantType type;


	/**
	 * Creates a new authorisation grant.
	 *
	 * @param type               The authorisation grant type. Must not be
	 *                           {@code null}.
	 */
	protected AuthorizationGrant(final GrantType type) {

		if (type == null)
			throw new IllegalArgumentException("The grant type must not be null");

		this.type = type;
	}


	/**
	 * Gets the authorisation grant type.
	 *
	 * @return The authorisation grant type.
	 */
	public GrantType getType() {

		return type;
	}


	/**
	 * Returns the request body parameters for the authorisation grant.
	 *
	 * @return The parameters.
	 */
	public abstract Map<String,List<String>> toParameters();


	/**
	 * Parses an authorisation grant from the specified request body
	 * parameters.
	 *
	 * @param params The request body parameters. Must not be {@code null}.
	 *
	 * @return The authorisation grant.
	 *
	 * @throws ParseException If parsing failed or the grant type is not
	 *                        supported.
	 */
	public static AuthorizationGrant parse(final Map<String,List<String>> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = MultivaluedMapUtils.getFirstValue(params, "grant_type");

		if (grantTypeString == null) {
			String msg = "Missing grant_type parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		GrantType grantType;
		try {
			grantType = GrantType.parse(grantTypeString);
		} catch (ParseException e) {
			String msg = "Invalid grant type: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + msg));
		}

		if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {
			return AuthorizationCodeGrant.parse(params);
		} else if (grantType.equals(GrantType.PRE_AUTHORIZED_CODE)) {
			return new PreAuthorizedCodeGrant(params);
		} else {
			throw new ParseException("Invalid or unsupported grant type: " + grantType, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}
	}
}
