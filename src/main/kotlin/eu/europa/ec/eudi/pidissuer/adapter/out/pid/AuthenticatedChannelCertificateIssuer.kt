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
import com.nimbusds.jose.JWSHeader.Builder
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.tlv.Tag
import eu.europa.ec.eudi.pidissuer.domain.tlv.buildTlv
import eu.europa.ec.eudi.pidissuer.domain.tlv.toSeTlv
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import java.time.Clock
import java.time.Instant
import java.util.Date

class AuthenticatedChannelCertificateIssuer(
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val calculateExpiresAt: TimeDependant<Instant>,
) {

    context(Raise<Unexpected>)
    operator fun invoke(
        holderKey: JWK,
    ): (ByteArray) -> Result<Base64URL> = {
        kotlin.runCatching {
            val issuerCert = issuerSigningKey.key.x509CertChain.first().let { X509CertUtils.parse(it.decode()) }
            val now = clock.instant().atZone(clock.zone)
            val cert = X509CertificateUtils.generate(
                issuerCert.subjectX500Principal,
                issuerCert.subjectX500Principal,
                Date.from(now.toInstant()),
                Date.from(calculateExpiresAt(now)),
                holderKey.toECKey().toECPublicKey(),
                issuerSigningKey.key.toECPrivateKey()
            )
            val header = with(Builder(issuerSigningKey.authenticatedChannelAlgorithm)) {
                keyID(issuerSigningKey.key.keyID)
                jwk(issuerSigningKey.key.toPublicJWK())
                x509CertChain((Base64.encode(cert.encoded)).prependTo(issuerSigningKey.key.x509CertChain))
                type(JOSEObjectType("vc+setlv"))
                build()
            }

            val headerTlv = header.toSeTlv()

            val signer = AuthenticatedChannelSigner(issuerSigningKey.key.toECPrivateKey(), holderKey)

            val signature = signer.sign(header, headerTlv + it)

            Base64URL.encode(buildTlv(Tag.HMAC, signature.decode()) + headerTlv + it)
        }
    }
}
