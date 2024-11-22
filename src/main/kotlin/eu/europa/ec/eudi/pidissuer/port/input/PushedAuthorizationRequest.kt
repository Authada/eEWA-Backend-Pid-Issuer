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
import arrow.core.raise.ensure
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import eu.europa.ec.eudi.pidissuer.adapter.out.email.EmailMdocScope
import eu.europa.ec.eudi.pidissuer.adapter.out.email.EmailSdJwtVcScope
import eu.europa.ec.eudi.pidissuer.adapter.out.email.EmailSdJwtVcScopeNew
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.MobileDrivingLicenceV1Scope
import eu.europa.ec.eudi.pidissuer.adapter.out.msisdn.MsisdnSdJwtVcScope
import eu.europa.ec.eudi.pidissuer.adapter.out.msisdn.MsisdnSdJwtVcScopeNew
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocScope
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidSdJwtVcScope
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidSdJwtVcScopeNew
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidSdJwtVcScopeNew2
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidSeTlvVcCertificateScope
import eu.europa.ec.eudi.pidissuer.domain.AuthorizationSession
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.ValidateWalletAttestation
import eu.europa.ec.eudi.pidissuer.patch.WalletClientAttestation
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

enum class AuthenticationType {
    EID,
    LOGIN,
    EMAIL_VERIFICATION,
    MSISDN_ATTESTATION,
    PREAUTHORIZED
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
    private val getAttributeDetails: GetAttributeDetails
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

        val type = attributeDetails.keys.map {
            when {
                it in MDL_SCOPES -> {
                    LOGGER.info("MDL requested")
                    AuthenticationType.LOGIN
                }

                it in PID_SCOPES -> {
                    LOGGER.info("PID requested")
                    AuthenticationType.EID
                }

                it in EMAIL_SCOPES -> {
                    LOGGER.info("Email requested")
                    AuthenticationType.EMAIL_VERIFICATION
                }

                it in MSISDN_SCOPES -> {
                    LOGGER.info("MSISDN requested")
                    AuthenticationType.MSISDN_ATTESTATION
                }

                else -> {
                    LOGGER.info("defaulting to PID requested")
                    AuthenticationType.EID
                }
            }
        }.toSet()

        ensure(type.size == 1) {
            raise(PARError.InvalidScope("Cannot have scopes with different authentication types in the same authorization request"))
        }

        LOGGER.info("Activated attribute details $attributeDetails")
        val session = AuthorizationSession(
            authRequest,
            attributeDetails,
            type.first()
        )
        storeAuthorizationSession(session)
        storeRequestUriReference(requestUri, authRequest.clientID.value, session.id)
        return RequestUri(requestUri, Instant.now().plus(Duration.ofMinutes(30))) //TODO move duration to config

    }


    companion object {
        val LOGGER: Logger = LoggerFactory.getLogger(PushedAuthorizationRequest::class.java)
        val PID_SCOPES =
            setOf(PidSdJwtVcScope, PidMsoMdocScope, PidSeTlvVcCertificateScope, PidSdJwtVcScopeNew, PidSdJwtVcScopeNew2)
        val MDL_SCOPES = setOf(MobileDrivingLicenceV1Scope)
        val EMAIL_SCOPES = setOf(EmailSdJwtVcScope, EmailMdocScope, EmailSdJwtVcScopeNew)
        val MSISDN_SCOPES = setOf(MsisdnSdJwtVcScope, MsisdnSdJwtVcScopeNew)
    }
}
