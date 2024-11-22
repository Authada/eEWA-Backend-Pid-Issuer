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
import com.nimbusds.oauth2.sdk.token.AccessTokenType
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.patch.TokenRequest
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequest
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json

class TokenApi(
    private val requestToken: AccessTokenRequest,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        POST(
            TOKEN_ENDPOINT,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.APPLICATION_JSON),
            ::handleAccessTokenRequest,
        )
    }

    private suspend fun handleAccessTokenRequest(request: ServerRequest): ServerResponse {
        log.info("Generating AccessToken Request response")
        return either {
            log.info("Converting ot Nimbus request")
            val nimbusHttpRequest = request.toNimbusRequest()
            log.info("Parsing tokenrequest")
            val tokenRequest = TokenRequest.parse(nimbusHttpRequest)
            val (accessToken, cnonce) = requestToken(tokenRequest, nimbusHttpRequest.dPoP)
            log.info("Successfully created accessToken")

            ServerResponse.ok()
                .json()
                .bodyValueAndAwait(AccessTokenResponse.success(accessToken, cnonce))
        }.getOrElse { error ->
            log.error("error generating access token {}", error)
            ServerResponse.badRequest()
                .buildAndAwait()
        }
    }

    companion object {
        const val TOKEN_ENDPOINT: String = "/wallet/token"
        private val log = LoggerFactory.getLogger(TokenApi::class.java)
    }

    @Serializable
    data class AccessTokenResponse(
        @SerialName("token_type")
        val tokenType: String,
        @SerialName("scope")
        val scope: List<String>? = null,
        @SerialName("access_token")
        val accessToken: String,
        @SerialName("expires_in")
        val expiresIn: Long,
        @SerialName("c_nonce")
        val cNonce: String,
        @SerialName("c_nonce_expires_in")
        val cNonceExpiresIn: Long,
        @SerialName("authorization_details")
        val authorizationDetails: List<JsonElement>? = null
    ) {
        companion object {
            fun success(dPoPAccessToken: DPoPAccessToken, cnonce: CNonce) =
                AccessTokenResponse(
                    expiresIn = dPoPAccessToken.lifetime,
                    tokenType = AccessTokenType.DPOP.value,
                    scope = dPoPAccessToken.scope?.toStringList(),
                    accessToken = dPoPAccessToken.value,
                    cNonce = cnonce.nonce,
                    cNonceExpiresIn = cnonce.expiresIn.seconds,
                    authorizationDetails = dPoPAccessToken.authorizationDetails?.map {
                        Json.parseToJsonElement(it.toJSONObject().toString())
                    }
                )

        }
    }

}

