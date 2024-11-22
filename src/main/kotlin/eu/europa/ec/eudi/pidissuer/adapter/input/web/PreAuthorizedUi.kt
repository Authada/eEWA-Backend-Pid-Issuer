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

import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait
import org.springframework.web.util.UriComponentsBuilder

class PreAuthorizedUi(
    private val issuerPublicUrl: HttpsUrl
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        GET(
            PREAUTHORIZED_OVERVIEW,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
        ) { handleOverview() }


    }

    private suspend fun handleOverview(): ServerResponse {
        log.info("Displaying 'Overview' page")
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "preauthorized-overview.html",
                mapOf(
                    "emailUri" to UriComponentsBuilder
                        .fromUri(issuerPublicUrl.value.toURI())
                        .path(EmailUi.EMAIL_VERIFICATION)
                        .build(),
                    "msisdnUri" to UriComponentsBuilder
                        .fromUri(issuerPublicUrl.value.toURI())
                        .path(MsisdnUi.MSISDN)
                        .build(),
                ),
            )
    }

    companion object {
        const val PREAUTHORIZED_OVERVIEW: String = "/preauthorized"
        private val log = LoggerFactory.getLogger(PreAuthorizedUi::class.java)
    }
}
