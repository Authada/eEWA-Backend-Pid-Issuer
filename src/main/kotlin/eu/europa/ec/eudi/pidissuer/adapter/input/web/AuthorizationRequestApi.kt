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
import com.nimbusds.oauth2.sdk.http.HTTPRequest
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationRequest
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationRequestError
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationRequestParams
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitBody
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json
import java.net.URI

suspend fun ServerRequest.toNimbusRequest(filter: ((String) -> String) = { it }): HTTPRequest {
    val httpRequest = HTTPRequest(Method.valueOf(method().name()), uri())
    httpRequest.body = filter.invoke(awaitBody())
    httpRequest.headerMap.putAll(headers().asHttpHeaders())
    return httpRequest
}

class AuthorizationRequestApi(
    private val authorize: AuthorizationRequest,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        GET(
            AUTHORIZATION_ENDPOINT,
            ::handleAuthorizationRequest,
        )
    }

    private suspend fun handleAuthorizationRequest(request: ServerRequest): ServerResponse {
        log.info("Generating Authorization Request response")
        val queryParams = request.queryParams()


        return either {
            val requestParams = AuthorizationRequestParams(
                clientId = queryParams.getFirst("client_id")!!,
                requestUri = URI.create(queryParams.getFirst("request_uri")!!)
            )
            val requestUri = authorize(requestParams)
            log.info("Successfully authenticated authentication request. requestUri: '{}'", requestUri)

            ServerResponse.status(HttpStatus.FOUND)
                .location(requestUri).buildAndAwait()
        }.getOrElse { error ->
            ServerResponse.badRequest()
                .json()
                .bodyValueAndAwait(AuthorizationRequestResponseTO.error(error))
        }
    }

    companion object {
        const val AUTHORIZATION_ENDPOINT: String = "/wallet/authorization"
        private val log = LoggerFactory.getLogger(AuthorizationRequestApi::class.java)
    }

    @Serializable
    data class AuthorizationRequestResponseTO(
        @SerialName("error") val error: String? = null,
    ) {
        companion object {
            fun error(error: AuthorizationRequestError) =
                AuthorizationRequestResponseTO(error = error::class.java.simpleName)
        }
    }

}
