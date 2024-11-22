/*
 * Copyright (c) 2023 European Commission
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
 *
 * Modified by AUTHADA GmbH
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
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.domain.MSO_MDOC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.SE_TLV_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.input.GetPreauthorizedCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitFormData
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class IssuerUi(
    private val credentialsOfferUri: String,
    private val metadata: CredentialIssuerMetaData,
    private val createCredentialsOffer: CreateCredentialsOffer,
    private val generateQrCode: GenerateQqCode,
    private val issuerPublicUrl: HttpsUrl,
    private val getPreauthorizedCode: GetPreauthorizedCode
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        // Display 'generate credentials offer' form
        GET(
            HOME,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
        ) { handleDisplayHome() }

        // Display 'generate credentials offer' form
        GET(
            GENERATE_CREDENTIALS_OFFER,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
        ) { handleDisplayGenerateCredentialsOfferForm() }


        // Submit 'generate credentials offer' form
        POST(
            GENERATE_CREDENTIALS_OFFER,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
            ::handleGenerateCredentialsOffer,
        )

        GET(
            GENERATE_CREDENTIALS_OFFER_PREAUTHORIZED,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
            ::handleGenerateCredentialsOfferPreauthorized
        )
    }

    private suspend fun handleDisplayGenerateCredentialsOfferForm(): ServerResponse {
        log.info("Displaying 'Generate Credentials Offer' page")
        val credentialIds = metadata.credentialConfigurationsSupported.mapNotNull {
            when (it) {
                is MsoMdocCredentialConfiguration -> CredentialOfferItem(it.id.value, it.docType, MSO_MDOC_FORMAT_VALUE)
                is SdJwtVcCredentialConfiguration -> CredentialOfferItem(
                    it.id.value,
                    it.docType,
                    SD_JWT_VC_FORMAT_VALUE
                )

                is SeTlvVcCredentialConfiguration -> null
            }
        }.filter {
            !(it.docType.contains("msisdn", true)|| it.docType.contains("pid", true))
        }
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "generate-credentials-offer-form.html",
                mapOf(
                    "credentialOffers" to credentialIds,
                    "credentialsOfferUri" to credentialsOfferUri,
                    "authorizationCodePath" to GENERATE_CREDENTIALS_OFFER
                ),
            )
    }

    private suspend fun handleDisplayHome(): ServerResponse {
        log.info("Displaying 'Home' page")
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "home.html",
                mapOf(
                    "authorizationCodeUri" to UriComponentsBuilder
                        .fromUri(issuerPublicUrl.value.toURI())
                        .path(GENERATE_CREDENTIALS_OFFER)
                        .build(),
                    "preAuthorizedCodeUri" to UriComponentsBuilder
                        .fromUri(issuerPublicUrl.value.toURI())
                        .path(PreAuthorizedUi.PREAUTHORIZED_OVERVIEW)
                        .build(),
                ),
            )
    }


    @Serializable
    data class CredentialOfferItem(val id: String, val docType: String, val format: String)

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun handleGenerateCredentialsOffer(request: ServerRequest): ServerResponse {
        log.info("Generating Credentials Offer")
        val formData = request.awaitFormData()
        val credentialIds = formData["credentialIds"]
            .orEmpty()
            .map(::CredentialConfigurationId)
            .toSet()
        val credentialsOfferUri = formData["credentialsOfferUri"]?.firstOrNull { it.isNotBlank() }

        return either {
            val credentialsOffer = createCredentialsOffer(credentialIds, credentialsOfferUri)
            log.info("Successfully generated Credentials Offer. URI: '{}'", credentialsOffer)

            val qrCode =
                generateQrCode(credentialsOffer, Format.PNG, Dimensions(Pixels(300u), Pixels(300u))).getOrThrow()
            log.info("Successfully generated QR Code. Displaying generated Credentials Offer.")
            ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "display-credentials-offer.html",
                    mapOf(
                        "uri" to credentialsOffer.toString(),
                        "qrCode" to Base64.encode(qrCode),
                        "qrCodeMediaType" to "image/png",
                        "backPath" to GENERATE_CREDENTIALS_OFFER
                    ),
                )
        }.getOrElse { error ->
            log.warn("Unable to generated Credentials Offer. Error: {}", error)
            ServerResponse.badRequest()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-error.html",
                    mapOf("error" to error::class.java.canonicalName)
                )
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun handleGenerateCredentialsOfferPreauthorized(request: ServerRequest): ServerResponse {
        log.info("Generating Credentials Offer")
        val queryParams = request.queryParams()


        return either {
            val requestUri =
                queryParams.getFirst("request_uri") ?: throw IllegalArgumentException("Missing required query param")
            val preAuthorizedCodeData = getPreauthorizedCode(URI.create(requestUri))
            val credentialsOffer = createCredentialsOffer(
                preAuthorizedCodeData.configurationIds,
                credentialsOfferUri,
                preAuthorizedCodeData.code
            )
            log.info("Successfully generated Credentials Offer. URI: '{}'", credentialsOffer)

            val qrCode =
                generateQrCode(credentialsOffer, Format.PNG, Dimensions(Pixels(300u), Pixels(300u))).getOrThrow()
            log.info("Successfully generated QR Code. Displaying generated Credentials Offer.")
            ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "display-credentials-offer.html",
                    mapOf(
                        "uri" to credentialsOffer.toString(),
                        "qrCode" to Base64.encode(qrCode),
                        "qrCodeMediaType" to "image/png",
                        "backPath" to PreAuthorizedUi.PREAUTHORIZED_OVERVIEW
                    ),
                )
        }.getOrElse { error ->
            log.warn("Unable to generated Credentials Offer. Error: {}", error)
            ServerResponse.badRequest()
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "generate-credentials-offer-error.html",
                    mapOf("error" to error::class.java.canonicalName)
                )
        }
    }

    companion object {
        const val GENERATE_CREDENTIALS_OFFER: String = "/credentialsOffer/authorizationcode"
        const val GENERATE_CREDENTIALS_OFFER_PREAUTHORIZED: String = "/credentialsOffer/preauthorizedcode"
        const val HOME: String = "/"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}
