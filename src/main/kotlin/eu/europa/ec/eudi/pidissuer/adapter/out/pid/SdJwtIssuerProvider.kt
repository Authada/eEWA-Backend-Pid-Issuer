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

import arrow.core.raise.Raise
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwtIssuer

fun interface SdJwtIssuerProvider {
    context(Raise<IssueCredentialError.Unexpected>)
    operator fun invoke(
        hashAlgorithm: HashAlgorithm,
        issuerSigningKey: IssuerSigningKey,
        verifierKa: VerifierKA?,
    ): SdJwtIssuer<SignedJWT>
}
