/*
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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.raise.Raise
import com.eygraber.uri.Uri
import com.eygraber.uri.Uri.Companion
import com.eygraber.uri.toURI
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerUi
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.util.UUID

sealed interface AuthorizationCodeError {

    data object Generic : AuthorizationCodeError
}

class GenerateAuthorizationReturnUrl(
    private val getAuthorizationSessionByRequestUriOnce: GetAuthorizationSessionByRequestUriOnce,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val createAuthorizationCodeUri: CreateAuthorizationCodeUri,
    private val issuerPublicUrl: HttpsUrl
) {
    context(Raise<AuthorizationCodeError>)
    suspend operator fun invoke(requestUri: URI, clientId: String): URI {
        val session = getAuthorizationSessionByRequestUriOnce(requestUri, clientId)
        val newRequestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}")
        storeRequestUriReference(newRequestUri, clientId, session.id)
        return if (session.authenticationType == AuthenticationType.PREAUTHORIZED) {
            UriComponentsBuilder.fromUriString(issuerPublicUrl.externalForm)
                .path(IssuerUi.GENERATE_CREDENTIALS_OFFER_PREAUTHORIZED)
                .queryParam("request_uri", newRequestUri.toString())
                .build()
                .encode()
                .toUri()
        } else {
            createAuthorizationCodeUri(
                session.authRequest.redirectionURI,
                newRequestUri.toString(),
                session.authRequest.state
            )
        }
    }
}
