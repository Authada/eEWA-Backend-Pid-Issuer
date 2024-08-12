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
package eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc

import COSE.OneKey
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithmId
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import id.walt.mdoc.cose.COSECryptoProvider
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.toKotlinInstant
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.util.Date
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration

@OptIn(ExperimentalEncodingApi::class)
internal class MsoMdocAuthenticatedChannelSigner<in Credential>(
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val validityDuration: Duration,
    private val docType: MsoDocType,
    private val usage: MDocBuilder.(Credential) -> Unit,
) {

    init {
        require(validityDuration.isPositive()) { "Validity duration must be positive" }
    }

    suspend fun sign(credential: Credential, deviceKey: ECKey, verifierKA: VerifierKA): String =
        withContext(Dispatchers.IO) {
            val ephKeyPair = ECKeyGenerator(issuerSigningKey.key.curve)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(Date()) // issued-at timestamp (optional)
                .generate()
            val issuerCert = issuerSigningKey.key.x509CertChain.first().let { X509CertUtils.parse(it.decode()) }
            val cert = X509CertificateUtils.generate(
                issuerCert.subjectX500Principal,
                issuerCert.subjectX500Principal, //TODO generate new principal
                Date.from(Instant.now()),
                Date.from(Instant.now() + java.time.Duration.ofMinutes(10)),
                ephKeyPair.toECPublicKey(),
                issuerSigningKey.key.toECPrivateKey()
            )
            val validityInfo = validityInfo()
            val deviceKeyInfo = deviceKeyInfo(deviceKey.toECKey())

            val mdoc = MDocBuilder(docType)
                .apply {
                    usage(credential)
                }
                .sign(validityInfo, deviceKeyInfo, createCryptoProvider(ephKeyPair, cert, verifierKA), ephKeyPair.keyID)
            Base64.UrlSafe.encode(mdoc.issuerSigned.toMapElement().toCBOR())
        }

    private fun createCryptoProvider(key: ECKey, cert: X509Certificate, verifierKA: VerifierKA): COSECryptoProvider =
        AuthenticatedChannelCOSECryptoProvider(
            listOf(
                AuthenticatedChannelCOSECryptoProviderKeyInfo(
                    keyID = key.keyID,
                    algorithmID = issuerSigningKey.authenticatedChannelAlgorithmId,
                    publicKey = key.toECPublicKey(),
                    privateKey = key.toECPrivateKey(),
                    x5Chain = listOf(cert) + X509CertChainUtils.parse(issuerSigningKey.key.x509CertChain),
                    trustedRootCAs = emptyList(),
                ),
            ),
            verifierKA
        )


    private fun validityInfo(): ValidityInfo {
        val signedAt = clock.instant().toKotlinInstant()
        val validTo = signedAt + validityDuration
        return ValidityInfo(signed = signedAt, validFrom = signedAt, validUntil = validTo, expectedUpdate = null)
    }

    private fun deviceKeyInfo(deviceKey: ECKey): DeviceKeyInfo {
        val key = OneKey(deviceKey.toECPublicKey(), null)
        val deviceKeyDataElement: MapElement = DataElement.fromCBOR(key.AsCBOR().EncodeToBytes())
        return DeviceKeyInfo(deviceKeyDataElement, null, null)
    }
}
