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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptySet
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.Encode
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm

const val SD_JWT_VC_FORMAT_VALUE = "vc+sd-jwt"
val SD_JWT_VC_FORMAT = Format(SD_JWT_VC_FORMAT_VALUE)

typealias SdJwtVcType = String

/**
 * @param type As defined in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-00#type-claim
 */
data class SdJwtVcCredentialConfiguration<T>(
    override val id: CredentialConfigurationId,
    override val docType: SdJwtVcType,
    override val scope: Scope? = null,
    override val display: List<CredentialDisplay>,
    val claims: List<AttributeDetails>,
    override val encode: Encode<T>,
    override val issuerSigningKey: IssuerSigningKey,
    override val issuerId: CredentialIssuerId,
) : CredentialConfiguration<T>{
    val order: List<String> = claims.map { it.name }
    override val format: Format
        get() = SD_JWT_VC_FORMAT
    override val cryptographicBindingMethodsSupported: NonEmptySet<CryptographicBindingMethod> = nonEmptySetOf(CryptographicBindingMethod.Jwk)
    override val credentialSigningAlgorithmsSupported: NonEmptySet<JWSAlgorithm> = setOf(
        issuerSigningKey.signingAlgorithm,
        issuerSigningKey.authenticatedChannelAlgorithm
    ).toNonEmptySetOrNull()!!
    override val proofTypesSupported: NonEmptySet<ProofType> = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256)))
}

//
// Credential Offer
//
data class SdJwtVcCredentialRequest(
    override val unvalidatedProof: UnvalidatedProof,
    override val credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
    val type: SdJwtVcType,
    val claims: Set<String> = emptySet(),
    override val verifierKA: VerifierKA?,
) : CredentialRequest {
    override val format: Format = SD_JWT_VC_FORMAT
}

context(Raise<String>)
internal fun SdJwtVcCredentialRequest.validate(meta: SdJwtVcCredentialConfiguration<*>) {
    ensure(type == meta.docType) { "doctype is $type but was expecting ${meta.docType}" }
    if (meta.claims.isEmpty()) {
        ensure(claims.isEmpty()) { "Requested claims should be empty. " }
    } else {
        val expectedAttributeNames = meta.claims.map { it.name }
        claims.forEach { name ->
            ensure(name in expectedAttributeNames) { "Unexpected attribute $name" }
        }
    }
}
