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
import eu.europa.ec.eudi.pidissuer.adapter.out.email.CreatePreauthorizedEmailSession
import eu.europa.ec.eudi.pidissuer.adapter.out.email.Email
import eu.europa.ec.eudi.pidissuer.adapter.out.email.StoreEmailData
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequest.Companion.PREAUTHORIZED_CLIENTID
import eu.europa.ec.eudi.pidissuer.port.input.GenerateAuthorizationReturnUrl
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitFormData
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait
import java.net.URI
import kotlin.jvm.optionals.getOrElse

class EmailUi(
    private val authorizationReturnUrl: GenerateAuthorizationReturnUrl,
    private val storeEmailData: StoreEmailData,
    private val createPreauthorizedEmailSession: CreatePreauthorizedEmailSession
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        // Display 'Login' form
        GET(
            EMAIL_VERIFICATION,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
            ::handleEmailForm
        )

        // Submit 'Login' form
        POST(
            EMAIL_VERIFICATION,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
            ::handleEmail,
        )
    }

    //TODO add proper error and session handling
    private suspend fun handleEmail(request: ServerRequest): ServerResponse {
        log.info("Handle 'Email' form")
        val formData = request.awaitFormData()
        val requestUri = formData.getFirst("request_uri") ?: throw IllegalArgumentException()
        val clientId = formData.getFirst("client_id") ?: throw IllegalArgumentException()
        val email = formData.getFirst("email") ?: throw IllegalArgumentException()
        val tan = formData.getFirst("tan")
        return either {
            if (email.isBlank() || (tan?.isBlank() == true)) {
                ServerResponse.status(HttpStatus.BAD_REQUEST)
                    .buildAndAwait()
            } else if (tan.isNullOrBlank()) {
                ServerResponse.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .renderAndAwait(
                        "email-form.html",
                        mapOf(
                            "emailUri" to EMAIL_VERIFICATION,
                            "requestUri" to requestUri,
                            "clientId" to clientId,
                            "email" to email,
                            "tan" to null,
                        ),
                    )
            } else {
                storeEmailData(URI.create(requestUri), clientId, Email(email))
                val redirectUrl = authorizationReturnUrl(URI.create(requestUri), clientId)
                ServerResponse.status(HttpStatus.FOUND)
                    .location(
                        redirectUrl
                    )
                    .buildAndAwait()
            }
        }.getOrElse {
            ServerResponse.status(HttpStatus.BAD_REQUEST)
                .buildAndAwait()
        }
    }

    //TODO add proper error and session handling
    private suspend fun handleEmailForm(request: ServerRequest): ServerResponse {
        log.info("Displaying 'Email' page")
        val requestUri: String = request.queryParam("request_uri").getOrElse {
            createPreauthorizedEmailSession().toString()
        }
        val clientId: String? = request.queryParam("client_id").getOrElse {
            PREAUTHORIZED_CLIENTID
        }
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "email-form.html",
                mapOf(
                    "emailUri" to EMAIL_VERIFICATION,
                    "requestUri" to requestUri,
                    "clientId" to clientId,
                    "email" to null,
                    "tan" to null,
                ),
            )
    }

    companion object {
        const val EMAIL_VERIFICATION: String = "/email"
        private val log = LoggerFactory.getLogger(EmailUi::class.java)
    }
}
