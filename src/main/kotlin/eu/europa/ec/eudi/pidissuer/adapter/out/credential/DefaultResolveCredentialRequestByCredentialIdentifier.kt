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
package eu.europa.ec.eudi.pidissuer.adapter.out.credential

import eu.europa.ec.eudi.pidissuer.domain.CredentialIdentifier
import eu.europa.ec.eudi.pidissuer.domain.CredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.RequestedResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.UnvalidatedProof
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.out.credential.ResolveCredentialRequestByCredentialIdentifier

typealias CredentialRequestFactory = (UnvalidatedProof, RequestedResponseEncryption, VerifierKA?) -> CredentialRequest

class DefaultResolveCredentialRequestByCredentialIdentifier(
    private val factories: Map<CredentialIdentifier, CredentialRequestFactory>,
) : ResolveCredentialRequestByCredentialIdentifier {

    override suspend fun invoke(
        identifier: CredentialIdentifier,
        unvalidatedProof: UnvalidatedProof,
        credentialResponseEncryption: RequestedResponseEncryption,
        verifierKA: VerifierKA?
    ): CredentialRequest? =
        factories[identifier]?.let { factory -> factory(unvalidatedProof, credentialResponseEncryption, verifierKA) }
}
