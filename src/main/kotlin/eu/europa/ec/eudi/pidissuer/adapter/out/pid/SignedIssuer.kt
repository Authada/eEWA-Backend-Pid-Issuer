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
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.SD_JWT_VC_FORMAT_VALUE
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwtFactory
import eu.europa.ec.eudi.sdjwt.SdJwtIssuer
import eu.europa.ec.eudi.sdjwt.nimbus

object SignedIssuer : SdJwtIssuerProvider {
    /**
     * Creates a Nimbus-based SD-JWT issuer
     * according to the requirements of SD-JWT VC
     * - No decoys
     * - JWS header kid should contain the id of issuer's key
     * - JWS header typ should contain value "vs+sd-jwt"
     * In addition the issuer will use the config to select
     * [HashAlgorithm], [JWSAlgorithm] and [issuer's key][ECKey]
     */
    context(Raise<Unexpected>)
    override fun invoke(
        hashAlgorithm: HashAlgorithm,
        issuerSigningKey: IssuerSigningKey,
        verifierKa: VerifierKA?
    ): SdJwtIssuer<SignedJWT> {
        val sdJwtFactory = SdJwtFactory(hashAlgorithm = hashAlgorithm, numOfDecoysLimit = 0)
        val signer = ECDSASigner(issuerSigningKey.key)
        return SdJwtIssuer.nimbus(sdJwtFactory, signer, issuerSigningKey.signingAlgorithm) {
            // SD-JWT VC requires the kid & typ header attributes
            // Check [here](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#name-jose-header)
            keyID(issuerSigningKey.key.keyID)
            jwk(issuerSigningKey.key.toPublicJWK())
            type(JOSEObjectType(SD_JWT_VC_FORMAT_VALUE))
            x509CertChain(issuerSigningKey.key.x509CertChain!!)
        }
    }

}
