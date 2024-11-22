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
package eu.europa.ec.eudi.pidissuer.adapter.out.email

import arrow.core.getOrElse
import arrow.core.raise.either
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.ClientID
import eu.europa.ec.eudi.pidissuer.domain.AuthorizationSession
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequest.Companion.PREAUTHORIZED_CLIENTID
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType
import eu.europa.ec.eudi.pidissuer.port.input.GetAttributeDetails
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreAuthorizationSession
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import java.net.URI
import java.util.UUID

class CreatePreauthorizedEmailSession(
    private val storeAuthorizationSession: StoreAuthorizationSession,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val getAttributeDetails: GetAttributeDetails
) {
    suspend operator fun invoke(): URI {
        val scope = Scope(EmailSdJwtVcScope.value, EmailMdocScope.value, EmailSdJwtVcScopeNew.value)
        val authorizationSession = AuthorizationSession(
            authenticationType = AuthenticationType.PREAUTHORIZED,
            matchedAttributeDetails = either {
                getAttributeDetails(
                    scope,
                    null
                )
            }.getOrElse {
                throw IllegalStateException()
            },
            authRequest = AuthorizationRequest.Builder(ResponseType.CODE, ClientID(PREAUTHORIZED_CLIENTID))
                .scope(scope)
                .build()
        )
        storeAuthorizationSession(authorizationSession)
        val requestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}")
        storeRequestUriReference(requestUri = requestUri, PREAUTHORIZED_CLIENTID, authorizationSession.id)
        return requestUri
    }
}
