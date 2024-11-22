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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Base abstract class for client authentication at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section 2.2.
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15), section 2.
 * </ul>
 */
public abstract class ClientAuthentication {


    /**
     * The client authentication method.
     */
    private final ClientAuthenticationMethod method;


    /**
     * The client ID.
     */
    private final ClientID clientID;


    /**
     * Creates a new abstract client authentication.
     *
     * @param method   The client authentication method. Must not be
     *                 {@code null}.
     * @param clientID The client identifier. Must not be {@code null}.
     */
    protected ClientAuthentication(final ClientAuthenticationMethod method, final ClientID clientID) {

        if (method == null)
            throw new IllegalArgumentException("The client authentication method must not be null");

        this.method = method;


        if (clientID == null)
            throw new IllegalArgumentException("The client identifier must not be null");

        this.clientID = clientID;
    }


    /**
     * Returns the client authentication method.
     *
     * @return The client authentication method.
     */
    public ClientAuthenticationMethod getMethod() {

        return method;
    }


    /**
     * Returns the client identifier.
     *
     * @return The client identifier.
     */
    public ClientID getClientID() {

        return clientID;
    }


    /**
     * Returns the name of the form parameters, if such are used by the
     * authentication method.
     *
     * @return The form parameter names, empty set if none.
     */
    public abstract Set<String> getFormParameterNames();


    /**
     * Parses the specified HTTP request for a supported client
     * authentication (see {@link ClientAuthenticationMethod}). This method
     * is intended to aid parsing of authenticated
     * {@link com.nimbusds.oauth2.sdk.TokenRequest}s.
     *
     * @param httpRequest The HTTP request to parse. Must not be
     *                    {@code null}.
     * @return The client authentication method, {@code null} if none or
     * the method is not supported.
     * @throws ParseException If the inferred client authentication
     *                        couldn't be parsed.
     */
    public static ClientAuthentication parse(final HTTPRequest httpRequest)
            throws ParseException {

        logger.info("Checking method");
        // The other methods require HTTP POST with URL-encoded params
        if (httpRequest.getMethod() != HTTPRequest.Method.POST &&
                !httpRequest.getEntityContentType().matches(ContentType.APPLICATION_URLENCODED)) {
            return null; // no auth
        }

        logger.info("parsing form parameters");
        Map<String, List<String>> params = httpRequest.getBodyAsFormParameters();

        // Do we have a signed JWT assertion?
        if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion")) && StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {

            logger.info("parsing wallet client attestion");
            return WalletClientAttestation.Companion.fromFormData(params);
        }
        logger.info("no auth provided");

        return null; // no auth
    }


    /**
     * Applies the authentication to the specified HTTP request by setting
     * its Authorization header and/or POST entity-body parameters
     * (according to the implemented client authentication method).
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     */
    public abstract void applyTo(final HTTPRequest httpRequest);

    static Logger logger = LoggerFactory.getLogger(ClientAuthentication.class);
}
