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
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import java.net.URI
import java.util.UUID
import kotlin.math.log


//TODO Spezifikaiton checken
/**
 * Errors that might be returned by [CreateCredentialsOffer].
 */
sealed interface AuthorizationRequestError {

    /**
     * No Credentials Unique Ids have been provided.
     */
    data object Test : AuthorizationRequestError

    /**
     * The provided Credential Unique Ids are not valid.
     */
    data class InvalidRequest(val test: String) : AuthorizationRequestError
}


data class AuthorizationRequestParams(
    val clientId: String,
    val requestUri: URI,
)

class AuthorizationRequest(
    private val getAuthorizationSessionByRequestUriOnce: GetAuthorizationSessionByRequestUriOnce,
    private val storeRequestUriReference: StoreRequestUriReference
) {
    context(Raise<AuthorizationRequestError>)
    suspend operator fun invoke(requestParams: AuthorizationRequestParams): URI {
        val session = getAuthorizationSessionByRequestUriOnce(requestParams.requestUri, requestParams.clientId)
        val requestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}")
        //TODO store request uri Object
//        val requestUriObject = RequestUri(uri = requestUri, expiration = Instant.now() + Duration.ofMinutes(10))
        storeRequestUriReference(requestUri, requestParams.clientId, session.id)
        return requestUri
    }
}
