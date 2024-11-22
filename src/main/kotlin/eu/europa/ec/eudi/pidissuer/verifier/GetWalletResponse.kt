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
package eu.europa.ec.eudi.pidissuer.verifier

import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitEntity
import org.springframework.web.reactive.function.client.awaitExchange
import org.springframework.web.util.UriComponentsBuilder
import java.net.URL

class GetWalletResponse(
    private val webClient: WebClient,
    private val verifierUri: URL
) {
    suspend operator fun invoke(transactionId: String, responseCode: String): WalletResponseTO {
        val uri = UriComponentsBuilder.fromUriString(verifierUri.toExternalForm())
            .path("/ui/presentations/${transactionId}")
            .queryParam("response_code", responseCode)
            .build()
            .toUri()
        return webClient.get()
            .uri(uri)
            .accept(MediaType.APPLICATION_JSON)
            .awaitExchange {
                it.awaitEntity<WalletResponseTO>().body!!
            }
    }
}
