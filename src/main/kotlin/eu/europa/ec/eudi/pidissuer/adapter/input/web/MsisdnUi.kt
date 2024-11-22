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
import eu.europa.ec.eudi.pidissuer.adapter.out.msisdn.AuthorizeMsisdn
import eu.europa.ec.eudi.pidissuer.adapter.out.msisdn.CreatePreauthorizedMsisdnSession
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequest.Companion.PREAUTHORIZED_CLIENTID
import eu.europa.ec.eudi.pidissuer.port.input.GenerateAuthorizationReturnUrl
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait
import java.net.URI
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.optionals.getOrElse
import kotlin.jvm.optionals.getOrNull

class MsisdnUi(
    private val createPreauthorizedMsisdnSession: CreatePreauthorizedMsisdnSession,
    private val authorizeMsisdn: AuthorizeMsisdn,
    private val generateAuthorizationReturnUrl: GenerateAuthorizationReturnUrl,
    private val generateQrCode: GenerateQqCode,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        // Display 'Login' form
        GET(
            MSISDN,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
            ::handleMsisdnForm
        )
    }

    //TODO add proper error and session handling
    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun handleMsisdnForm(request: ServerRequest): ServerResponse {
        log.info("Displaying 'MSISDN' page")
        val requestUri: URI = request.queryParam("request_uri").map {
            URI.create(it)
        }.getOrElse {
            createPreauthorizedMsisdnSession()
        }

        val clientId: String = request.queryParam("client_id").getOrElse {
            PREAUTHORIZED_CLIENTID
        }

        val responseCode = request.queryParam("response_code").getOrNull()

        return if (responseCode != null) {
            authorizeMsisdn.complete(requestUri, clientId, responseCode)

            either {
                val returnUrl =
                    generateAuthorizationReturnUrl(requestUri, clientId)
                ServerResponse.status(HttpStatus.FOUND)
                    .location(returnUrl)
                    .buildAndAwait()
            }.getOrElse {
                ServerResponse.badRequest()
                    .buildAndAwait()
            }
        } else {
            val url = authorizeMsisdn.start(requestUri, clientId)

            val qrCode =
                generateQrCode(url, Format.PNG, Dimensions(Pixels(300u), Pixels(300u))).getOrThrow()
            ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "msisdn.html",
                    mapOf(
                        "requestUri" to requestUri,
                        "clientId" to clientId,
                        "openid4vpUrl" to url,
                        "qrCode" to Base64.encode(qrCode),
                        "qrCodeMediaType" to "image/png",
                    ),
                )
        }
    }

    companion object {
        const val MSISDN: String = "/msisdn"
        private val log = LoggerFactory.getLogger(MsisdnUi::class.java)
    }
}
