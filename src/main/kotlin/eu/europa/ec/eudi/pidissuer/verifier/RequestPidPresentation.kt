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
 */package eu.europa.ec.eudi.pidissuer.verifier

import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.prex.Constraints
import eu.europa.ec.eudi.prex.Constraints.LimitDisclosure.REQUIRED
import eu.europa.ec.eudi.prex.FieldConstraint
import eu.europa.ec.eudi.prex.Filter
import eu.europa.ec.eudi.prex.Format
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.InputDescriptor
import eu.europa.ec.eudi.prex.InputDescriptorId
import eu.europa.ec.eudi.prex.JsonPath
import eu.europa.ec.eudi.prex.Name
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.Purpose
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.util.UUID

data class PresentationSession(
    val uri: URI,
    val transactionId: String,
)

class RequestPidPresentation(
    private val initTransaction: InitTransaction
) {
    suspend operator fun invoke(redirectUrlTemplate: String, vararg fields: AttributeDetails): PresentationSession {
        val uuid = UUID.randomUUID().toString()
        val transactionData = initTransaction(
            InitTransactionTO(
                type = PresentationTypeTO.VpTokenRequest,
                presentationDefinition = PresentationDefinition(
                    id = Id(uuid),
                    purpose = Purpose("PID presentation for msisdn attestation issuing"),
                    inputDescriptors = listOf(
                        InputDescriptor(
                            id = InputDescriptorId("eu.europa.ec.eudi.pid.1"),
                            name = Name("EUDI PID"),
                            format = Format.format(buildJsonObject {
                                putJsonObject("vc+sd-jwt") {
                                    putJsonArray("sd-jwt_alg_values") {
                                        arrayOf(
                                            "ES256",
                                            "ES384",
                                            "ES512",
                                            "DVS-P256-SHA256-HS256"
                                        ).forEach {
                                            add(it)
                                        }
                                    }
                                    putJsonArray("kb-jwt_alg_values") {
                                        arrayOf(
                                            "ES256",
                                            "ES384",
                                            "ES512",
                                        ).forEach {
                                            add(it)
                                        }
                                    }
                                }
                            }),
                            constraints = Constraints.of(
                                fs = fields.map {
                                    FieldConstraint(
                                        paths = listOf(JsonPath.jsonPath("$.${it.name}")!!),
                                        intentToRetain = false
                                    )
                                } + FieldConstraint(
                                    paths = listOf(JsonPath.jsonPath("\$.vct")!!),
                                    filter = Filter.filter(buildJsonObject {
                                        this.put("type", JsonPrimitive("string"))
                                        this.putJsonArray("enum") {
                                            this.add("https://metadata-8c062a.usercontent.opencode.de/pid.json")
                                            this.add("https://example.bmi.bund.de/credential/pid/1.0")
                                            this.add("urn:eu.europa.ec.eudi:pid:1")
                                        }
                                    }),
                                    intentToRetain = false
                                ),
                                limitDisclosure = REQUIRED
                            )!!
                        )
                    )
                ),
                redirectUriTemplate = redirectUrlTemplate,
                nonce = uuid
            )
        )
        return PresentationSession(
            uri = UriComponentsBuilder.fromUriString("openid4vp://")
                .queryParam("request_uri", transactionData.requestUri)
                .queryParam("client_id", transactionData.clientId)
                .encode()
                .build()
                .toUri(),
            transactionId = transactionData.transactionId
        )
    }
}
