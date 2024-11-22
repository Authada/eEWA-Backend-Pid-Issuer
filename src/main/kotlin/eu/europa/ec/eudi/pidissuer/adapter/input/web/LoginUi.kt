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

class LoginUi(
    private val generateAuthorizationCode: GenerateAuthorizationReturnUrl,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        // Display 'Login' form
        GET(
            LOGIN,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
            ::handleLoginForm
        )

        // Submit 'Login' form
        POST(
            LOGIN,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
            ::handleLogin,
        )
    }

    //TODO add proper error and session handling
    private suspend fun handleLogin(request: ServerRequest): ServerResponse {
        log.info("Handle 'Login' form")
        val formData = request.awaitFormData()
        val requestUri = formData.getFirst("request_uri") ?: throw IllegalArgumentException()
        val clientId = formData.getFirst("client_id") ?: throw IllegalArgumentException()
        return either {
            val authorizationCodeUri = generateAuthorizationCode(URI.create(requestUri), clientId)
            ServerResponse.status(HttpStatus.FOUND)
                .location(
                    authorizationCodeUri
                )
                .buildAndAwait()
        }.getOrElse {
            ServerResponse.status(HttpStatus.BAD_REQUEST)
                .buildAndAwait()
        }
    }

    //TODO add proper error and session handling
    private suspend fun handleLoginForm(request: ServerRequest): ServerResponse {
        log.info("Displaying 'Login' page")
        val requestUri = request.queryParam("request_uri").orElseThrow()
        val clientId = request.queryParam("client_id").orElseThrow()
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "login-form.html",
                mapOf(
                    "requestUri" to requestUri,
                    "clientId" to clientId,
                ),
            )
    }


    companion object {
        const val LOGIN: String = "/issuer/login"
        private val log = LoggerFactory.getLogger(LoginUi::class.java)
    }
}
