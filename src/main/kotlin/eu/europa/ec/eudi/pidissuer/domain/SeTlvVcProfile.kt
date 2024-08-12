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
package eu.europa.ec.eudi.pidissuer.domain

import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import com.nimbusds.jose.JWSAlgorithm

const val SE_TLV_FORMAT_VALUE = "vc+se-tlv"
val SE_TLV_FORMAT = Format(SE_TLV_FORMAT_VALUE)

@JvmInline
value class SeTlvVcType(val value: String)

data class SeTlvVcCredentialConfiguration(
    override val id: CredentialConfigurationId,
    val type: SeTlvVcType,
    override val scope: Scope? = null,
    override val cryptographicBindingMethodsSupported: NonEmptySet<CryptographicBindingMethod>,
    override val credentialSigningAlgorithmsSupported: NonEmptySet<JWSAlgorithm>,
    override val display: List<CredentialDisplay>,
    val claims: List<AttributeDetails>,
    override val proofTypesSupported: NonEmptySet<ProofType>,
) : CredentialConfiguration

data class SeTlvVcCredentialRequest(
    override val unvalidatedProof: UnvalidatedProof,
    override val credentialResponseEncryption: RequestedResponseEncryption = RequestedResponseEncryption.NotRequired,
    val type: SeTlvVcType,
    val claims: Set<String> = emptySet(),
    override val verifierKA: VerifierKA?,
) : CredentialRequest {
    override val format: Format = SE_TLV_FORMAT
}

context(Raise<String>)
internal fun SeTlvVcCredentialRequest.validate(meta: SeTlvVcCredentialConfiguration) {
    ensure(type == meta.type) { "doctype is $type but was expecting ${meta.type}" }
    if (meta.claims.isEmpty()) {
        ensure(claims.isEmpty()) { "Requested claims should be empty. " }
    } else {
        val expectedAttributeNames = meta.claims.map { it.name }
        claims.forEach { name ->
            ensure(name in expectedAttributeNames) { "Unexpected attribute $name" }
        }
    }
}
