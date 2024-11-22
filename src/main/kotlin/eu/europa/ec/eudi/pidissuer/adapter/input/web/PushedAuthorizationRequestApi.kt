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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import arrow.core.getOrElse
import arrow.core.raise.either
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryWalletAttestationNonceRepository
import eu.europa.ec.eudi.pidissuer.domain.WAVError
import eu.europa.ec.eudi.pidissuer.domain.WalletAttestationNonce
import eu.europa.ec.eudi.pidissuer.patch.WalletClientAttestation
import eu.europa.ec.eudi.pidissuer.port.input.PARError
import eu.europa.ec.eudi.pidissuer.port.input.PushedAuthorizationRequest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitFormData
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json
import java.net.URI
import java.time.Clock
import java.time.Duration

class PushedAuthorizationRequestApi(
    private val createPAR: PushedAuthorizationRequest,
    private val clock: Clock,
    private val inMemoryWalletAttestationNonceRepository: InMemoryWalletAttestationNonceRepository
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        POST(
            PAR_ENDPOINT,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.APPLICATION_JSON),
            ::handlePAR,
        )
        GET(
            PAR_ENDPOINT,
            accept(MediaType.APPLICATION_JSON),
        ) { getPARNonce() }
    }

    private suspend fun getPARNonce(): ServerResponse {
        log.info("Generating PAR nonce response")

        return ServerResponse.status(HttpStatus.OK)
            .json()
            .bodyValueAndAwait(PARNonceResponseTO.success(inMemoryWalletAttestationNonceRepository.new()))

    }

    private suspend fun handlePAR(request: ServerRequest): ServerResponse {
        log.info("Generating PAR nonce")

        return either {
            val formData = request.awaitFormData().toMap()
            log.info("Formdata {}", formData)
            val authRequest = AuthorizationRequest.parse(formData)
            val clientAssertion: WalletClientAttestation =
                WalletClientAttestation.fromFormData(formData) ?: raise(PARError.InvalidClientAssertion)
            val (requestUri, expiration) = createPAR(authRequest, clientAssertion)
            val expiresIn = Duration.between(clock.instant(), expiration).toSeconds()
            log.info("Successfully generated PAR. ExpiresIn: {} URI: '{}'", expiresIn, requestUri)

            ServerResponse.status(HttpStatus.CREATED)
                .json()
                .bodyValueAndAwait(PARResponseTO.success(expiresIn, requestUri))
        }.getOrElse { error ->
            ServerResponse.badRequest()
                .json()
                .bodyValueAndAwait(PARResponseTO.error(error))
        }
    }

    companion object {
        const val PAR_ENDPOINT: String = "/wallet/par"
        private val log = LoggerFactory.getLogger(PushedAuthorizationRequestApi::class.java)
    }

    @Serializable
    data class PARResponseTO(
        @SerialName("expires_in") val expiresIn: Long? = null,
        @SerialName("request_uri") val requestUri: String? = null,
        @SerialName("error") val error: String? = null,
        @SerialName("error_description") val errorDescription: String? = null,
    ) {
        companion object {
            fun success(expiresIn: Long, requestUri: URI) =
                PARResponseTO(
                    expiresIn = expiresIn,
                    requestUri = requestUri.toString()
                )

            fun error(error: PARError) =
                PARResponseTO(
                    error = error::class.java.simpleName,
                    errorDescription = when (error) {
                        is PARError.InvalidAuthorizationDetails -> error.description
                        else -> null
                    }
                )

            fun error(error: WAVError) =
                PARResponseTO(error = error::class.java.simpleName)
        }
    }


    @Serializable
    data class PARNonceResponseTO(
        @SerialName("c_nonce_expires_in") val expiresIn: Long,
        @SerialName("c_nonce") val cnonce: String,
    ) {
        companion object {
            fun success(cnonce: WalletAttestationNonce) =
                PARNonceResponseTO(
                    expiresIn = cnonce.expiresIn.seconds,
                    cnonce = cnonce.nonce
                )
        }
    }

}
