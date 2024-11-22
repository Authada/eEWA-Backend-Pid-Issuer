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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.raise.Raise
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.MobileDrivingLicenceV1Namespace
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Attributes.pidAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocNamespace
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocScope
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidSdJwtVcScope
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidMdocAttributes
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.MSO_MDOC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.SE_TLV_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcCredentialConfiguration

class GetAttributeDetails(
    private val metadata: CredentialIssuerMetaData
) {
    context(Raise<PARError>)
    operator fun invoke(
        scope: Scope?,
        authorizationDetails: List<AuthorizationDetail>?
    ): Map<eu.europa.ec.eudi.pidissuer.domain.Scope, List<AttributeDetails>> {
        val result: Map<eu.europa.ec.eudi.pidissuer.domain.Scope, List<AttributeDetails>> =
            if (scope?.toStringList().isNullOrEmpty().not()) {
                metadata.credentialConfigurationsSupported.filter { it.scope!!.value in scope!!.toStringList() }.map {
                    it.scope!! to when (it) {
                        is MsoMdocCredentialConfiguration -> it.msoClaims.values.flatMap { it }
                        is SdJwtVcCredentialConfiguration -> it.claims
                        is SeTlvVcCredentialConfiguration -> it.claims
                    }
                }.toMap()
            } else if (authorizationDetails.isNullOrEmpty().not()) {
                authorizationDetails!!.map { details ->
                    val credConfId = details.getStringField("credential_configuration_id")
                    val format = details.getStringField("format")

                    val (foundScope, availableClaims) = if (credConfId != null) {
                        getAttributesForConfigurationId(credConfId)
                    } else if (format != null) {
                        getAttributesforFormat(format)
                    } else {
                        throw IllegalStateException()
                    }

                    val claims = details.getJSONObjectField("claims")

                    val requestedClaims = (claims?.get(PidMsoMdocNamespace) as? Map<*, *>)?.keys
                        ?: (claims?.get(MobileDrivingLicenceV1Namespace) as? Map<*, *>)?.keys
                        ?: claims?.keys

                    val requestedAttributeDetails =
                        if (!requestedClaims.isNullOrEmpty()) {
                            availableClaims.filter { available ->
                                requestedClaims.filterIsInstance<String>().any { it.startsWith(available.name, true) }
                            }.takeIf { it.isNotEmpty() }
                        } else availableClaims

                    foundScope to (requestedAttributeDetails ?: emptyList())
                }.toMap()
            } else {
                throw IllegalArgumentException()
            }
        return result
    }

    @Suppress("UNCHECKED_CAST")
    private fun getAttributesforFormat(
        format: String
    ): Pair<eu.europa.ec.eudi.pidissuer.domain.Scope, List<AttributeDetails>> {

        return when (format) {
            MSO_MDOC_FORMAT_VALUE -> {
                PidMsoMdocScope to mapOf(pidMdocAttributes).flatMap {
                    it.value.filter {
                        it.operationSetter != null
                    }
                }
            }

            SD_JWT_VC_FORMAT_VALUE -> {
                PidSdJwtVcScope to pidAttributes.filter {
                    it.operationSetter != null
                }
            }

            SE_TLV_FORMAT_VALUE -> {
                PidSdJwtVcScope to pidAttributes.filter {
                    it.operationSetter != null
                }
            }

            else -> throw IllegalArgumentException()
        }
    }

    private fun getAttributesForConfigurationId(credConfId: String?): Pair<eu.europa.ec.eudi.pidissuer.domain.Scope, List<AttributeDetails>> {
        val config = credentialConfiguration(credConfId)
        return when (config) {
            is MsoMdocCredentialConfiguration -> {
                config.scope!! to config.msoClaims.flatMap {
                    it.value.filter { it.operationSetter != null }
                }
            }

            is SdJwtVcCredentialConfiguration -> {
                config.scope!! to config.claims.filter { it.operationSetter != null }
            }

            is SeTlvVcCredentialConfiguration -> {
                config.scope!! to config.claims.filter { it.operationSetter != null }
            }

            null -> throw IllegalArgumentException()
        }
    }

    private fun credentialConfiguration(credConfId: String?): CredentialConfiguration<*>? {
        val config = metadata.credentialConfigurationsSupported.find {
            it.id.value == credConfId
        }
        return config
    }
}
