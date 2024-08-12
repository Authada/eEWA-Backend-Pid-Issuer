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

import arrow.core.prependTo
import arrow.core.raise.Raise
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwtFactory
import eu.europa.ec.eudi.sdjwt.SdJwtIssuer
import eu.europa.ec.eudi.sdjwt.nimbus
import java.time.Duration
import java.time.Instant
import java.util.Date

object AuthenticatedChannelIssuer : SdJwtIssuerProvider {


    context(Raise<Unexpected>)
    override fun invoke(
        hashAlgorithm: HashAlgorithm,
        issuerSigningKey: IssuerSigningKey,
        verifierKa: VerifierKA?,
    ): SdJwtIssuer<SignedJWT> {
        val sdJwtFactory = SdJwtFactory(hashAlgorithm = hashAlgorithm, numOfDecoysLimit = 0)
        val ephKeyPair = ECKeyGenerator(issuerSigningKey.key.curve).generate()
        val issuerCert = issuerSigningKey.key.x509CertChain.first().let { X509CertUtils.parse(it.decode()) }
        val cert = X509CertificateUtils.generate(
            issuerCert.subjectX500Principal,
            issuerCert.subjectX500Principal,
            Date.from(Instant.now()),
            Date.from(Instant.now() + Duration.ofMinutes(10)),
            ephKeyPair.toECPublicKey(),
            issuerSigningKey.key.toECPrivateKey()
        )
        val signer = AuthenticatedChannelSigner(ephKeyPair.toECPrivateKey(), verifierKa!!.key)
        return SdJwtIssuer.nimbus(sdJwtFactory, signer, issuerSigningKey.authenticatedChannelAlgorithm) {
            keyID(issuerSigningKey.key.keyID)
            jwk(ephKeyPair.toPublicJWK())
            x509CertChain((Base64.encode(cert.encoded)).prependTo(issuerSigningKey.key.x509CertChain))
            type(JOSEObjectType("vc+sd-jwt"))
            customParam("rpk", verifierKa.key.toJSONObject())
        }
    }

}
