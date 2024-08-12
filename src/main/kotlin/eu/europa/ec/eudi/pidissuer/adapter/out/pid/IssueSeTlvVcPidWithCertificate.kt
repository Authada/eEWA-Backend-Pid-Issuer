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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.domain.CNonce
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIdentifier
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponse
import eu.europa.ec.eudi.pidissuer.domain.CryptographicBindingMethod
import eu.europa.ec.eudi.pidissuer.domain.IssuedCredential
import eu.europa.ec.eudi.pidissuer.domain.ProofType
import eu.europa.ec.eudi.pidissuer.domain.SE_TLV_FORMAT
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcCredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcType
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.time.Clock

val PidSeTlvVcCertificateScope: Scope = Scope("${PID_DOCTYPE}_vc_se_tlv_issuing")

private val log = LoggerFactory.getLogger(IssueSeTlvVcPidWithCertificate::class.java)

fun pidSeTlvVcV1WithCertificate(vararg signingAlgorithm: JWSAlgorithm): SeTlvVcCredentialConfiguration =
    SeTlvVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSeTlvVcCertificateScope.value),
        type = SeTlvVcType(pidDocType(1) + "_issuing"),
        display = pidDisplay,
        claims = Attributes.pidAttributes,
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = signingAlgorithm.toSet().toNonEmptySetOrNull()!!,
        scope = PidSeTlvVcCertificateScope,
        proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
    )

/**
 * Service for issuing PID SD JWT credential
 */
class IssueSeTlvVcPidWithCertificate(
    credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val getPidData: GetPidData,
    private val extractJwkFromCredentialKey: ExtractJwkFromCredentialKey,
    private val notificationsEnabled: Boolean,
    private val generateNotificationId: GenerateNotificationId,
    private val storeIssuedCredential: StoreIssuedCredential,
    issuer: AuthenticatedChannelCertificateIssuer
) : IssueSpecificCredential<JsonElement> {

    private val validateProof = ValidateProof(credentialIssuerId)

    override val supportedCredential: SeTlvVcCredentialConfiguration =
        pidSeTlvVcV1WithCertificate(issuerSigningKey.authenticatedChannelAlgorithm)
    override val publicKey: JWK
        get() = issuerSigningKey.key.toPublicJWK()

    private val encodePidInSeTlvVcCertificate = EncodePidInSeTlvVcCertificate(
        issuer,
    )

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val sdJwt = encodePidInSeTlvVcCertificate(pid, pidMetaData, holderPubKey.await())

        val notificationId =
            if (notificationsEnabled) generateNotificationId()
            else null
        storeIssuedCredential(
            IssuedCredential(
                format = SE_TLV_FORMAT,
                type = supportedCredential.type.value,
                holderPublicKey = holderPubKey.await().toPublicJWK(),
                issuedAt = clock.instant(),
                notificationId = notificationId,
            ),
        )

        CredentialResponse.Issued(JsonPrimitive(sdJwt.toString()), notificationId)
            .also {
                log.info("Successfully issued PID")
                log.debug("Issued PID data {}", it)
            }
    }

    context(Raise<InvalidProof>)
    private suspend fun holderPubKey(
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): JWK {
        val key = validateProof(request.unvalidatedProof, expectedCNonce, supportedCredential)
        return extractJwkFromCredentialKey(key)
            .getOrElse {
                raise(InvalidProof("Unable to extract JWK from CredentialKey", it))
            }
    }
}
