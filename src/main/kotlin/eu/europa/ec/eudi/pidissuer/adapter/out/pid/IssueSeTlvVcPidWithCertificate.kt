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
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.CryptographicBindingMethod
import eu.europa.ec.eudi.pidissuer.domain.ProofType
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcCredentialConfiguration

val PidSeTlvVcCertificateScope: Scope = Scope("${PID_DOCTYPE}_vc_se_tlv_issuing")

fun pidSeTlvVcV1WithCertificate(
    issuerSigningKey: IssuerSigningKey,
    issuerId: CredentialIssuerId,
    issuer: AuthenticatedChannelCertificateIssuer
): SeTlvVcCredentialConfiguration<Pid> =
    SeTlvVcCredentialConfiguration(
        id = CredentialConfigurationId(PidSeTlvVcCertificateScope.value),
        docType = pidDocType(1) + "_issuing",
        display = pidDisplay,
        claims = Attributes.pidAttributes,
        cryptographicBindingMethodsSupported = nonEmptySetOf(CryptographicBindingMethod.Jwk),
        credentialSigningAlgorithmsSupported = setOf(
            issuerSigningKey.signingAlgorithm,
            issuerSigningKey.authenticatedChannelAlgorithm
        ).toNonEmptySetOrNull()!!,
        scope = PidSeTlvVcCertificateScope,
        proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
        issuerId = issuerId,
        issuerSigningKey = issuerSigningKey,
        encode = EncodePidInSeTlvVcCertificate(issuer)
    )
