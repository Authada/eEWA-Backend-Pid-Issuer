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
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.util.URIUtils
import eu.europa.ec.eudi.pidissuer.adapter.input.web.EidApi.Companion.TCTOKEN_ENDPOINT
import eu.europa.ec.eudi.pidissuer.adapter.input.web.EmailUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.LoginUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MsisdnUi
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType.EID
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType.EMAIL_VERIFICATION
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType.LOGIN
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType.MSISDN_ATTESTATION
import eu.europa.ec.eudi.pidissuer.port.input.AuthenticationType.PREAUTHORIZED
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GetAuthorizationSessionByRequestUriOnce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import org.slf4j.LoggerFactory
import org.springframework.web.util.UriComponentsBuilder
import org.springframework.web.util.UriUtils
import java.net.URI
import java.util.UUID


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
    private val storeRequestUriReference: StoreRequestUriReference,
    private val publicIssuerURI: HttpsUrl
) {
    context(Raise<AuthorizationRequestError>)
    suspend operator fun invoke(requestParams: AuthorizationRequestParams): URI {
        val session = getAuthorizationSessionByRequestUriOnce(requestParams.requestUri, requestParams.clientId)
        val requestUri = URI("urn:ietf:params:oauth:request_uri:${UUID.randomUUID()}")

        val redirectUri = when(session.authenticationType) {
            EID -> createEidUrl(requestUri, requestParams.clientId)
            LOGIN -> createLoginUrl(requestUri, requestParams.clientId)
            EMAIL_VERIFICATION -> createEmailVerificationUrl(requestUri, requestParams.clientId)
            MSISDN_ATTESTATION -> createMsisdnUrl(requestUri, requestParams.clientId)
            PREAUTHORIZED -> throw IllegalStateException()
        }

        storeRequestUriReference(requestUri, requestParams.clientId, session.id)
        return redirectUri
    }

    private fun createEidUrl(
        requestUri: URI,
        clientId: String
    ) = UriComponentsBuilder.fromUriString("eid://127.0.0.1:24727/eID-Client")
        .queryParam(
            "tcTokenURL", createTcTokenUrl(requestUri, clientId)
        )
        .encode()
        .build()
        .toUri()
        .also {
            log.info("Eid-URL: {}", it)
        }

    private fun createLoginUrl(
        requestUri: URI,
        clientId: String
    ) = UriComponentsBuilder.fromUriString(publicIssuerURI.externalForm)
        .path(LoginUi.LOGIN)
        .queryParam(
            "request_uri", requestUri.toString()
        )
        .queryParam(
            "client_id", clientId
        )
        .encode()
        .build()
        .toUri()
        .also {
            log.info("Login-URL: {}", it)
        }

    private fun createEmailVerificationUrl(
        requestUri: URI,
        clientId: String
    ) = UriComponentsBuilder.fromUriString(publicIssuerURI.externalForm)
        .path(EmailUi.EMAIL_VERIFICATION)
        .queryParam(
            "request_uri", requestUri.toString()
        )
        .queryParam(
            "client_id", clientId
        )
        .encode()
        .build()
        .toUri()
        .also {
            log.info("EMAIL_VERIFICATION-URL: {}", it)
        }

    private fun createMsisdnUrl(
        requestUri: URI,
        clientId: String
    ) = UriComponentsBuilder.fromUriString(publicIssuerURI.externalForm)
        .path(MsisdnUi.MSISDN)
        .queryParam(
            "request_uri", requestUri.toString()
        )
        .queryParam(
            "client_id", clientId
        )
        .encode()
        .build()
        .toUri()
        .also {
            log.info("MSISDN-URL: {}", it)
        }

    private fun createTcTokenUrl(
        requestUri: URI,
        clientId: String
    ) = UriComponentsBuilder.fromUriString(publicIssuerURI.externalForm)
        .path(TCTOKEN_ENDPOINT)
        .queryParam("request_uri", requestUri)
        .queryParam(
            "client_id",
            clientId
        )
        .build()
        .encode()
        .toUriString()
        .also {
            log.info("TCTokenUrl: {}", it)
        }

    private val log = LoggerFactory.getLogger(AuthorizationRequest::class.java)
}
