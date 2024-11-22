/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParameterRequirement;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.*;
import eu.europa.ec.eudi.pidissuer.adapter.input.web.TokenApi;
import net.jcip.annotations.Immutable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;


/**
 * Token request. Used to obtain an
 * {@link com.nimbusds.oauth2.sdk.token.AccessToken access token} and an
 * optional {@link com.nimbusds.oauth2.sdk.token.RefreshToken refresh token}
 * at the Token endpoint of the authorisation server. Supports custom request
 * parameters.
 *
 * <p>Example token request with an authorisation code grant:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * grant_type=authorization_code
 * &amp;code=SplxlOBeZQQYbYS6WxSbIA
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.3, 4.3.2, 4.4.2 and 6.
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396), section 6.
 *     <li>Resource Indicators for OAuth 2.0 (RFC 8707)
 *     <li>OAuth 2.0 Incremental Authorization
 *         (draft-ietf-oauth-incremental-authz-04)
 * </ul>
 */
@Immutable
public class TokenRequest extends AbstractOptionallyIdentifiedRequest {


	/**
	 * The authorisation grant.
	 */
	private final AuthorizationGrant authzGrant;


	/**
	 * The requested scope, {@code null} if not specified.
	 */
	private final Scope scope;


	/**
	 * The RAR details (optional).
	 */
	private final List<AuthorizationDetail> authorizationDetails;
	
	
	/**
	 * The resource URI(s), {@code null} if not specified.
	 */
	private final List<URI> resources;
	
	
	/**
	 * Existing refresh token for incremental authorisation of a public
	 * client, {@code null} if not specified.
	 */
	private final RefreshToken existingGrant;


	/**
	 * Custom request parameters.
	 */
	private final Map<String,List<String>> customParams;


	private static final Set<String> ALLOWED_REPEATED_PARAMS = new HashSet<>(Arrays.asList("resource", "audience"));


	/**
	 * Creates a new token request with the specified client
	 * authentication.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(uri, clientAuth, authzGrant, scope, null, null);
	}


	/**
	 * Creates a new token request with the specified client
	 * authentication and extension and custom parameters.
	 *
	 * @param uri          The URI of the token endpoint. May be
	 *                     {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param clientAuth   The client authentication. Must not be
	 *                     {@code null}.
	 * @param authzGrant   The authorisation grant. Must not be
	 *                     {@code null}.
	 * @param scope        The requested scope, {@code null} if not
	 *                     specified.
	 * @param resources    The resource URI(s), {@code null} if not
	 *                     specified.
	 * @param customParams Custom parameters to be included in the request
	 *                     body, empty map or {@code null} if none.
	 */
	public TokenRequest(final URI uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<URI> resources,
			    final Map<String,List<String>> customParams) {

		this(uri, clientAuth, authzGrant, scope, null, resources, customParams);
	}


	/**
	 * Creates a new token request with the specified client
	 * authentication and extension and custom parameters.
	 *
	 * @param uri                  The URI of the token endpoint. May be
	 *                             {@code null} if the
	 *                             {@link #toHTTPRequest} method will not
	 *                             be used.
	 * @param clientAuth           The client authentication. Must not be
	 *                             {@code null}.
	 * @param authzGrant           The authorisation grant. Must not be
	 *                             {@code null}.
	 * @param scope                The requested scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The Rich Authorisation Request (RAR)
	 *                             details, {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param customParams         Custom parameters to be included in the
	 *                             request body, empty map or {@code null}
	 *                             if none.
	 */
	public TokenRequest(final URI uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<AuthorizationDetail> authorizationDetails,
			    final List<URI> resources,
			    final Map<String,List<String>> customParams) {

		super(uri, clientAuth);

		if (clientAuth == null)
			throw new IllegalArgumentException("The client authentication must not be null");

		this.authzGrant = authzGrant;

		this.scope = scope;

		if (resources != null) {
			for (URI resourceURI: resources) {
				if (! ResourceUtils.isLegalResourceURI(resourceURI))
					throw new IllegalArgumentException("Resource URI must be absolute and with no query or fragment: " + resourceURI);
			}
		}

		this.authorizationDetails = authorizationDetails;

		this.resources = resources;

		this.existingGrant = null; // only for confidential client

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = customParams;
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Creates a new token request with the specified client
	 * authentication.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URI uri,
			    final ClientAuthentication clientAuth,
			    final AuthorizationGrant authzGrant) {

		this(uri, clientAuth, authzGrant, null);
	}


	/**
	 * Creates a new token request, with no explicit client authentication
	 * (maybe present in the grant depending on its type).
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientID   The client identifier, {@code null} if not
	 *                   specified.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI uri,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(uri, clientID, authzGrant, scope, null, null,null);
	}


	/**
	 * Creates a new token request, with no explicit client authentication
	 * (maybe present in the grant depending on its type) and extension
	 * and custom parameters.
	 *
	 * @param uri           The URI of the token endpoint. May be
	 *                      {@code null} if the {@link #toHTTPRequest}
	 *                      method will not be used.
	 * @param clientID      The client identifier, {@code null} if not
	 *                      specified.
	 * @param authzGrant    The authorisation grant. Must not be
	 *                      {@code null}.
	 * @param scope         The requested scope, {@code null} if not
	 *                      specified.
	 * @param resources     The resource URI(s), {@code null} if not
	 *                      specified.
	 * @param existingGrant Existing refresh token for incremental
	 *                      authorisation of a public client, {@code null}
	 *                      if not specified.
	 * @param customParams  Custom parameters to be included in the request
	 *                      body, empty map or {@code null} if none.
	 */
	public TokenRequest(final URI uri,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<URI> resources,
			    final RefreshToken existingGrant,
			    final Map<String,List<String>> customParams) {

		this(uri, clientID, authzGrant, scope, null, resources, existingGrant, customParams);
	}


	/**
	 * Creates a new token request, with no explicit client authentication
	 * (maybe present in the grant depending on its type) and extension
	 * and custom parameters.
	 *
	 * @param uri                  The URI of the token endpoint. May be
	 *                             {@code null} if the
	 *                             {@link #toHTTPRequest}
	 *                             method will not be used.
	 * @param clientID             The client identifier, {@code null} if
	 *                             not specified.
	 * @param authzGrant           The authorisation grant. Must not be
	 *                             {@code null}.
	 * @param scope                The requested scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The Rich Authorisation Request (RAR)
	 *                             details, {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param existingGrant        Existing refresh token for incremental
	 *                             authorisation of a public client,
	 *                             {@code null} if not specified.
	 * @param customParams         Custom parameters to be included in the
	 *                             request body, empty map or {@code null}
	 *                             if none.
	 */
	public TokenRequest(final URI uri,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant,
			    final Scope scope,
			    final List<AuthorizationDetail> authorizationDetails,
			    final List<URI> resources,
			    final RefreshToken existingGrant,
			    final Map<String,List<String>> customParams) {

		super(uri, clientID);

		if (authzGrant.getType().requiresClientAuthentication()) {
			throw new IllegalArgumentException("The \"" + authzGrant.getType() + "\" grant type requires client authentication");
		}

		if (authzGrant.getType().requiresClientID() && clientID == null) {
			throw new IllegalArgumentException("The \"" + authzGrant.getType() + "\" grant type requires a \"client_id\" parameter");
		}

		this.authzGrant = authzGrant;

		this.scope = scope;

		this.authorizationDetails = authorizationDetails;

		if (resources != null) {
			for (URI resourceURI: resources) {
				if (! ResourceUtils.isLegalResourceURI(resourceURI))
					throw new IllegalArgumentException("Resource URI must be absolute and with no query or fragment: " + resourceURI);
			}
		}

		this.resources = resources;

		this.existingGrant = existingGrant;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = customParams;
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Creates a new token request, with no explicit client authentication
	 * (maybe present in the grant depending on its type).
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param clientID   The client identifier, {@code null} if not
	 *                   specified.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URI uri,
			    final ClientID clientID,
			    final AuthorizationGrant authzGrant) {

		this(uri, clientID, authzGrant, null);
	}


	/**
	 * Creates a new token request, without client authentication and a
	 * specified client identifier.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 * @param scope      The requested scope, {@code null} if not
	 *                   specified.
	 */
	public TokenRequest(final URI uri,
			    final AuthorizationGrant authzGrant,
			    final Scope scope) {

		this(uri, (ClientID)null, authzGrant, scope);
	}


	/**
	 * Creates a new token request, without client authentication and a
	 * specified client identifier.
	 *
	 * @param uri        The URI of the token endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   will not be used.
	 * @param authzGrant The authorisation grant. Must not be {@code null}.
	 */
	public TokenRequest(final URI uri,
			    final AuthorizationGrant authzGrant) {

		this(uri, (ClientID)null, authzGrant, null);
	}


	/**
	 * Returns the authorisation grant.
	 *
	 * @return The authorisation grant.
	 */
	public AuthorizationGrant getAuthorizationGrant() {

		return authzGrant;
	}


	/**
	 * Returns the requested scope.
	 *
	 * @return The requested scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	/**
	 * Returns the Rich Authorisation Request (RAR) details.
	 *
	 * @return The authorisation details, {@code null} if not specified.
	 */
	public List<AuthorizationDetail> getAuthorizationDetails() {

		return authorizationDetails;
	}
	
	
	/**
	 * Returns the resource server URI.
	 *
	 * @return The resource URI(s), {@code null} if not specified.
	 */
	public List<URI> getResources() {
		
		return resources;
	}
	
	
	/**
	 * Returns the existing refresh token for incremental authorisation of
	 * a public client, {@code null} if not specified.
	 *
	 * @return The existing grant, {@code null} if not specified.
	 */
	public RefreshToken getExistingGrant() {
		
		return existingGrant;
	}


	/**
	 * Returns the additional custom parameters included in the request
	 * body.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * resource=http://xxxxxx/PartyOData
	 * </pre>
	 *
	 * @return The additional custom parameters as an unmodifiable map,
	 *         empty map if none.
	 */
	public Map<String,List<String>> getCustomParameters () {

		return Collections.unmodifiableMap(customParams);
	}


	/**
	 * Returns the specified custom parameter included in the request body.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter value(s), {@code null} if not specified.
	 */
	public List<String> getCustomParameter(final String name) {

		return customParams.get(name);
	}


	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		if (getClientAuthentication() != null) {
			getClientAuthentication().applyTo(httpRequest);
		}

		Map<String, List<String>> params;
		try {
			params = new LinkedHashMap<>(httpRequest.getBodyAsFormParameters());
		} catch (ParseException e) {
			throw new SerializeException(e.getMessage(), e);
		}
		params.putAll(authzGrant.toParameters());

		switch (authzGrant.getType().getScopeRequirementInTokenRequest()) {
			case REQUIRED:
				if (CollectionUtils.isEmpty(scope)) {
					throw new SerializeException("Scope is required for the " + authzGrant.getType() + " grant");
				}
				params.put("scope", Collections.singletonList(scope.toString()));
				break;
			case OPTIONAL:
				if (CollectionUtils.isNotEmpty(scope)) {
					params.put("scope", Collections.singletonList(scope.toString()));
				}
				break;
			case NOT_ALLOWED:
			default:
				break;
		}

		if (getClientID() != null) {
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
		}

		if (getAuthorizationDetails() != null) {
			params.put("authorization_details", Collections.singletonList(AuthorizationDetail.toJSONString(getAuthorizationDetails())));
		}
		
		if (getResources() != null) {
			List<String> values = new LinkedList<>();
			for (URI uri: resources) {
				if (uri == null)
					continue;
				values.add(uri.toString());
			}
			params.put("resource", values);
		}
		
		if (getExistingGrant() != null) {
			params.put("existing_grant", Collections.singletonList(existingGrant.getValue()));
		}

		if (! getCustomParameters().isEmpty()) {
			params.putAll(getCustomParameters());
		}

		httpRequest.setBody(URLUtils.serializeParameters(params));

		return httpRequest;
	}


	/**
	 * Parses a token request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token request.
	 */
	public static TokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);

		// Parse client authentication, if any
		ClientAuthentication clientAuth;
		
		try {
			logger.info("Parsing client auth");
			clientAuth = ClientAuthentication.parse(httpRequest);
			logger.info("Parsed client auth");
		} catch (ParseException e) {
			throw new ParseException(e.getMessage(), OAuth2Error.INVALID_REQUEST.appendDescription(": " + e.getMessage()));
		}

		// No fragment! May use query component!
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		
		Set<String> repeatParams = MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, ALLOWED_REPEATED_PARAMS);
		if (! repeatParams.isEmpty()) {
			String msg = "Parameter(s) present more than once: " + repeatParams;
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.setDescription(msg));
		}

		// Parse grant
		logger.info("Parsing grant");
		AuthorizationGrant grant = AuthorizationGrant.parse(params);
		logger.info("Parsed grant");

		if (clientAuth == null && grant.getType().requiresClientAuthentication()) {
			String msg = "Missing client authentication";
			throw new ParseException(msg, OAuth2Error.INVALID_CLIENT.appendDescription(": " + msg));
		}

		// Parse client id
		ClientID clientID = null;

		if (clientAuth == null) {
			// Parse optional client ID
			String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

			if (clientIDString != null && ! clientIDString.trim().isEmpty())
				clientID = new ClientID(clientIDString);

			if (clientID == null && grant.getType().requiresClientID()) {
				String msg = "Missing required client_id parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}
		}

		// Parse optional scope
		String scopeValue = MultivaluedMapUtils.getFirstValue(params, "scope");

		ParameterRequirement scopeRequirement = grant.getType().getScopeRequirementInTokenRequest();

		Scope scope = null;

		if (scopeValue != null && (ParameterRequirement.REQUIRED.equals(scopeRequirement) || ParameterRequirement.OPTIONAL.equals(scopeRequirement))) {
			scope = Scope.parse(scopeValue);
		}

		// Parse optional RAR
		String json = MultivaluedMapUtils.getFirstValue(params, "authorization_details");

		List<AuthorizationDetail> authorizationDetails = null;

		if (json != null) {
			authorizationDetails = AuthorizationDetail.parseList(json);
		}
		
		// Parse optional resource URIs
		List<URI> resources = null;
		
		List<String> vList = params.get("resource");
		
		if (vList != null) {
			
			resources = new LinkedList<>();
			
			for (String uriValue: vList) {
				
				if (uriValue == null)
					continue;
				
				String errMsg = "Illegal resource parameter: Must be an absolute URI without a fragment: " + uriValue;
				
				URI resourceURI;
				try {
					resourceURI = new URI(uriValue);
				} catch (URISyntaxException e) {
					throw new ParseException(errMsg, OAuth2Error.INVALID_TARGET.setDescription(errMsg));
				}
				
				if (! ResourceUtils.isLegalResourceURI(resourceURI)) {
					throw new ParseException(errMsg, OAuth2Error.INVALID_TARGET.setDescription(errMsg));
				}
				
				resources.add(resourceURI);
			}
		}
		
		String rt = MultivaluedMapUtils.getFirstValue(params, "existing_grant");
		RefreshToken existingGrant = StringUtils.isNotBlank(rt) ? new RefreshToken(rt) : null;

		// Parse custom parameters
		Map<String,List<String>> customParams = new HashMap<>();

		for (Map.Entry<String,List<String>> p: params.entrySet()) {

			if (p.getKey().equalsIgnoreCase("grant_type")) {
				continue; // skip
			}

			if (p.getKey().equalsIgnoreCase("client_id")) {
				continue; // skip
			}

			if (p.getKey().equalsIgnoreCase("client_secret")) {
				continue; // skip
			}

			if (p.getKey().equalsIgnoreCase("client_assertion_type")) {
				continue; // skip
			}

			if (p.getKey().equalsIgnoreCase("client_assertion")) {
				continue; // skip
			}

			if (p.getKey().equalsIgnoreCase("scope")) {
				continue; // skip
			}

			if (p.getKey().equalsIgnoreCase("authorization_details")) {
				continue; // skip
			}
			
			if (p.getKey().equalsIgnoreCase("resource")) {
				continue; // skip
			}
			
			if (p.getKey().equalsIgnoreCase("existing_grant"))
				continue; // skip

			if (! grant.getType().getRequestParameterNames().contains(p.getKey())) {
				// We have a custom (non-registered) parameter
				customParams.put(p.getKey(), p.getValue());
			}
		}

		if (clientAuth != null) {
			return new TokenRequest(uri, clientAuth, grant, scope, authorizationDetails, resources, customParams);
		} else {
			// public client
			return new TokenRequest(uri, clientID, grant, scope, authorizationDetails, resources, existingGrant, customParams);
		}
	}

	static Logger logger = LoggerFactory.getLogger(TokenRequest.class);
}
