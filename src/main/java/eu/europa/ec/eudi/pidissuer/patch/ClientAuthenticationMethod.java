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


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * Client authentication method at the Token endpoint.
 *
 * <p>Constants are provided for four client authentication methods:
 *
 * <ul>
 *     <li>{@link #ATTEST_JWT_CLIENT_AUTH attest_jwt_client_auth}
 *     <li>{@link #NONE none}
 * </ul>
 *
 * <p>Use the constructor to define a custom client authentication method.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705), section 2.
 *     <li>OpenID Connect Federation 1.0.
 * </ul>
 */
@Immutable
public final class ClientAuthenticationMethod extends Identifier {
	
	
	private static final long serialVersionUID = 1L;

	/**
	 * The client is a public client as defined in OAuth 2.0 and does not
	 * have a client secret.
	 */
	public static final ClientAuthenticationMethod NONE =
		new ClientAuthenticationMethod("none");


	/**
	 * The client is a public client as defined in OAuth 2.0 and does not
	 * have a client secret.
	 */
	public static final ClientAuthenticationMethod ATTEST_JWT_CLIENT_AUTH =
		new ClientAuthenticationMethod("attest_jwt_client_auth");


	/**
	 * Gets the default client authentication method.
	 *
	 * @return {@link #NONE}
	 */
	public static ClientAuthenticationMethod getDefault() {

		return NONE;
	}


	/**
	 * Creates a new client authentication method with the specified value.
	 *
	 * @param value The authentication method value. Must not be 
	 *              {@code null} or empty string.
	 */
	public ClientAuthenticationMethod(final String value) {

		super(value);
	}


	/**
	 * Parses a client authentication method from the specified value.
	 *
	 * @param value The authentication method value. Must not be
	 *              {@code null} or empty string.
	 *
	 * @return The client authentication method.
	 */
	public static ClientAuthenticationMethod parse(final String value) {

		if (value.equals(NONE.getValue())) {
			return NONE;
		} else if (value.equals(ATTEST_JWT_CLIENT_AUTH.getValue())) {
			return ATTEST_JWT_CLIENT_AUTH;
		} else {
			return new ClientAuthenticationMethod(value);
		}
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ClientAuthenticationMethod &&
		       this.toString().equals(object.toString());
	}
}
