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
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.input.CreateTCToken
import eu.europa.ec.eudi.pidissuer.port.input.EidResultError
import eu.europa.ec.eudi.pidissuer.port.input.HandleEidResult
import eu.europa.ec.eudi.pidissuer.port.input.TCToken
import eu.europa.ec.eudi.pidissuer.port.input.TCTokenError
import eu.europa.ec.eudi.pidissuer.port.input.TCTokenError.CommunicationErrorAdress
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI

class EidApi(
    private val createTCToken: CreateTCToken,
    private val handleEidResult: HandleEidResult,
    private val issuerPublicUrl: HttpsUrl
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        GET(
            TCTOKEN_ENDPOINT,
            accept(MediaType.TEXT_XML),
            ::handleTCTokenRequest,
        )
        GET(
            REFRESHADDRESS_ENDPOINT,
            ::handleRefreshAddressRequest,
        )
        GET(
            COMMUNICATIONERRORADDRESS_ENDPOINT,
            ::handleCommunicationErrorAdress,
        )
    }

    private suspend fun handleTCTokenRequest(request: ServerRequest): ServerResponse {
        log.info("Generating TCToken response")
        val queryParams = request.queryParams()


        val clientId = queryParams.getFirst("client_id")!!
        return either {
            val requestUri = URI(queryParams.getFirst("request_uri")!!)
            val tcToken = createTCToken(requestUri, clientId)
            log.info("Successfully generated TCToken. TCToken: {}", tcToken)

            renderTCToken(TCTokenResponseTO.success(tcToken, issuerPublicUrl, clientId))
        }.getOrElse { error ->
            renderTCToken(TCTokenResponseTO.error(error, issuerPublicUrl, clientId))
        }
    }

    private suspend fun handleCommunicationErrorAdress(request: ServerRequest): ServerResponse {
        log.info("communication error, $request")
        return ServerResponse.status(HttpStatus.FOUND)
            .location(
                UriComponentsBuilder.fromUriString("eudi-openid4ci://authorize")
                    .queryParam("error", "Generic")
                    .queryParam("errorDescription", "Error during authentication")
                    .build().toUri()
            ).buildAndAwait()
    }

    private suspend fun renderTCToken(tcTokenResponseTO: TCTokenResponseTO): ServerResponse {
        return ServerResponse.ok()
            .contentType(MediaType(MediaType.TEXT_XML, Charsets.UTF_8))
            .renderAndAwait(
                "tctoken.xml",
                mapOf(
                    "psk" to tcTokenResponseTO.psk,
                    "serverAddress" to tcTokenResponseTO.serverAddress,
                    "sessionIdentifier" to tcTokenResponseTO.sessionIdentifier,
                    "refreshAddress" to tcTokenResponseTO.refreshAddress,
                    "communicationErrorAddress" to tcTokenResponseTO.communicationErrorAddress,
                )
            )
    }

    private suspend fun handleRefreshAddressRequest(request: ServerRequest): ServerResponse {
        log.info("HandlingRefreshAddress call")
        val formData = request.queryParams()

        return either {
            val requestUri = URI(formData.getFirst("request_uri")!!)
            val clientId = formData.getFirst("client_id")!!
            val resultMajor = formData.getFirst("ResultMajor")!!
            val authorizationCodeUri = handleEidResult(requestUri, clientId, resultMajor)
            log.info("Successfully received eid data. AuthorizationCode: {}", authorizationCodeUri)

            ServerResponse.status(HttpStatus.FOUND)
                .location(
                    authorizationCodeUri
                )
                .buildAndAwait()
        }.getOrElse { error ->
            when (error) {
                is EidResultError.RedirectError -> ServerResponse.status(HttpStatus.FOUND)
                    .location(
                        error.uri
                    ).buildAndAwait()

                else -> ServerResponse.status(HttpStatus.FOUND)
                    .location(
                        UriComponentsBuilder.fromUriString("eudi-openid4ci://authorize") //TODO get public uri
                            .queryParam("error", "Generic")
                            .queryParam("errorDescription", "Error during authentication")
                            .build().toUri()
                    ).buildAndAwait()
            }
        }
    }

    companion object {
        const val TCTOKEN_ENDPOINT: String = "/eid/tctoken"
        const val REFRESHADDRESS_ENDPOINT: String = "/eid/refresh"
        const val COMMUNICATIONERRORADDRESS_ENDPOINT: String = "/eid/error"
        private val log = LoggerFactory.getLogger(EidApi::class.java)
    }

    data class TCTokenResponseTO(
        val serverAddress: String? = null,
        val sessionIdentifier: String? = null,
        val refreshAddress: String? = null,
        val psk: String? = null,
        val communicationErrorAddress: String? = null
    ) {
        companion object {
            fun success(tcToken: TCToken, issuerPublicUrl: HttpsUrl, clientId: String) =
                TCTokenResponseTO(
                    serverAddress = tcToken.serverAddress,
                    sessionIdentifier = tcToken.sessionIdentifier,
                    refreshAddress = UriComponentsBuilder.fromUriString(issuerPublicUrl.externalForm)
                        .path(REFRESHADDRESS_ENDPOINT)
                        .queryParam("request_uri", tcToken.refreshAddressURI.toString())
                        .queryParam("client_id", clientId)
                        .encode()
                        .build()
                        .toUri()
                        .toString(),
                    psk = tcToken.psk,
                )

            fun error(error: TCTokenError, issuerPublicUrl: HttpsUrl, clientId: String) =
                when (error) {
                    is CommunicationErrorAdress -> TCTokenResponseTO(
                        communicationErrorAddress = UriComponentsBuilder.fromUriString(issuerPublicUrl.toString())
                            .path(COMMUNICATIONERRORADDRESS_ENDPOINT)
                            .queryParam("request_uri", error.communicationErrorAddressURI)
                            .queryParam("client_id", clientId)
                            .encode()
                            .build()
                            .toUri()
                            .toString()
                    )

                    else -> TCTokenResponseTO()
                }
        }
    }

}
