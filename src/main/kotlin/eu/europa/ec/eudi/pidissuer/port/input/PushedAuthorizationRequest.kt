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

import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Attributes.pidAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocNamespace
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidSdJwtVcScope
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.domain.AuthorizationSession
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.JwtVcJsonCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.MSO_MDOC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.SE_TLV_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.ValidateWalletAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreAuthorizationSession
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreRequestUriReference
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.UUID

sealed interface PARError {
    data object Test : PARError

    data class InvalidScope(val test: String) : PARError
    object InvalidClientAssertion : PARError
    data class InvalidAuthorizationDetails(val description: String) : PARError
}

data class RequestUri(
    val uri: URI,
    val expiration: Instant
)

class PushedAuthorizationRequest(
    private val storeAuthorizationSession: StoreAuthorizationSession,
    private val storeRequestUriReference: StoreRequestUriReference,
    private val credentialIssuerId: CredentialIssuerId,
    private val validateWalletAttestation: ValidateWalletAttestation,
    private val metadata: CredentialIssuerMetaData
) {
    context(Raise<PARError>)
    suspend operator fun invoke(
        authRequest: AuthorizationRequest,
        clientAssertion: WalletClientAttestation
    ): RequestUri {
        either {
            clientAssertion.validate { attestation, attestationPop ->
                validateWalletAttestation(
                    authRequest.clientID.value,
                    credentialIssuerId,
                    attestation,
                    attestationPop
                )
            }
        }.getOrElse {
            raise(PARError.InvalidClientAssertion)
        }
        val requestUriParam = UUID.randomUUID()
        val requestUri = URI("urn:ietf:params:oauth:request_uri:$requestUriParam")
        val attributeDetails = getAttributeDetails(authRequest.scope, authRequest.authorizationDetails)
        LOGGER.info("Activated attribute details $attributeDetails")
        val session = AuthorizationSession(
            authRequest,
            attributeDetails
        )
        storeAuthorizationSession(session)
        storeRequestUriReference(requestUri, authRequest.clientID.value, session.id)
        return RequestUri(requestUri, Instant.now().plus(Duration.ofMinutes(30)))

    }

    context(Raise<PARError>)
    private fun getAttributeDetails(
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
                        else -> throw IllegalStateException()
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

                    val requestedClaims = (claims?.get(PidMsoMdocNamespace) as? Map<*, *>)?.keys ?: claims?.keys

                    val requestedAttributeDetails =
                        if (!requestedClaims.isNullOrEmpty()) {
                            availableClaims.filter { it.name in requestedClaims }
                                .takeIf { it.isNotEmpty() }
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
                PidMsoMdocV1.scope!! to PidMsoMdocV1.msoClaims.flatMap {
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

            is JwtVcJsonCredentialConfiguration, null -> throw IllegalArgumentException()
        }
    }

    private fun credentialConfiguration(credConfId: String?): CredentialConfiguration? {
        val config = metadata.credentialConfigurationsSupported.find {
            it.id.value == credConfId
        }
        return config
    }

    companion object {
        val LOGGER: Logger = LoggerFactory.getLogger(PushedAuthorizationRequest::class.java)
    }
}
