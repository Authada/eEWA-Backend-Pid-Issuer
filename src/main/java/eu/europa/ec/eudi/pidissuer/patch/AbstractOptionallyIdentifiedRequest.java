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
 */

package eu.europa.ec.eudi.pidissuer.patch;


import com.nimbusds.oauth2.sdk.id.ClientID;

import java.net.URI;


/**
 * Abstract request with optional client authentication or client
 * identification.
 *
 * <p>Client authentication methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic client_secret_basic}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretPost client_secret_post}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretJWT client_secret_jwt}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT private_key_jwt}
 * </ul>
 *
 * <p>Client identification methods:
 *
 * <ul>
 *     <li>Top level {@code client_id} parameter.
 * </ul>
 */
public abstract class AbstractOptionallyIdentifiedRequest extends AbstractOptionallyAuthenticatedRequest {


	/**
	 * The client identifier, {@code null} if not specified.
	 */
	private final ClientID clientID;
	


	/**
	 * Creates a new abstract request with optional client authentication.
	 *
	 * @param uri        The URI of the endpoint (HTTP or HTTPS) for which
	 *                   the request is intended, {@code null} if not
	 *                   specified (if, for example, the
	 *                   {@link #toHTTPRequest()} method will not be used).
	 * @param clientAuth The client authentication, {@code null} if none.
	 */
	protected AbstractOptionallyIdentifiedRequest(final URI uri,
						      final ClientAuthentication clientAuth) {

		super(uri, clientAuth);
		clientID = null;
	}


	/**
	 * Creates a new abstract request with optional client identification.
	 *
	 * @param uri      The URI of the endpoint (HTTP or HTTPS) for which
	 *                 the request is intended, {@code null} if not
	 *                 specified (if, for example, the
	 *                 {@link #toHTTPRequest()} method will not be used).
	 * @param clientID The client identifier, {@code null} if not
	 *                 specified.
	 */
	protected AbstractOptionallyIdentifiedRequest(final URI uri,
						      final ClientID clientID) {

		super(uri, null);
		this.clientID = clientID;
	}


	/**
	 * Gets the client identifier (for a request from a public client or a
	 * request without explicit client authentication).
	 *
	 * @see #getClientAuthentication()
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return clientID;
	}
}
