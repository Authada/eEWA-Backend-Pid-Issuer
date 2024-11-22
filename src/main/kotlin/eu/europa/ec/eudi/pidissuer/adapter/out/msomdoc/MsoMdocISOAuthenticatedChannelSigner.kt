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
import com.nimbusds.jose.crypto.impl.ECDH
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.cryptoProvider
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import eu.europa.ec.eudi.pidissuer.domain.VerifierKA
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.docrequest.MDocRequestBuilder
import id.walt.mdoc.mdocauth.DeviceAuthentication
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.toKotlinInstant
import java.time.Clock
import java.util.Date
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration

@OptIn(ExperimentalEncodingApi::class)
internal class MsoMdocISOAuthenticatedChannelSigner<in Credential>(
    private val clock: Clock,
    private val issuerSigningKey: IssuerSigningKey,
    private val validityDuration: Duration,
    private val docType: MsoDocType,
    private val usage: MDocBuilder.(Credential) -> Unit,
) {

    init {
        require(validityDuration.isPositive()) { "Validity duration must be positive" }
    }


    private val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        issuerSigningKey.cryptoProvider()
    }

    suspend fun sign(credential: Credential, verifierKA: VerifierKA): String =
        withContext(Dispatchers.IO) {
            val ephDevKeyPair = ECKeyGenerator(issuerSigningKey.key.curve)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(Date()) // issued-at timestamp (optional)
                .generate()
            val validityInfo = validityInfo()
            val deviceKeyInfo = deviceKeyInfo(ephDevKeyPair.toECKey())
            val sharedSecret =
                ECDH.deriveSharedSecret(verifierKA.key.toECKey().toECPublicKey(), ephDevKeyPair.toECPrivateKey(), null)
            val items = MapElement(MDocBuilder(docType).apply {
                usage(credential)
            }.nameSpacesMap.values.flatten().associate {
                MapKey(it.elementIdentifier.value) to it.elementValue
            })
            val mdoc = MDocBuilder(docType)
                .sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, ephDevKeyPair.keyID)
                .presentWithDeviceMAC(
                    MDocRequestBuilder(docType)
                        .apply {
                            items.value.keys.forEach {
                                this.addDataElementRequest(docType, it.str, false)
                            }
                        }.build(),
                    DeviceAuthentication(
                        ListElement(), //TODO transceive session transcript
                        docType,
                        EncodedCBORElement(
                            MapElement(
                                mapOf(
                                    MapKey(docType) to items
                                )
                            )
                        )
                    ),
                    sharedSecret.encoded
                )
            Base64.UrlSafe.encode(mdoc.issuerSigned.toMapElement().toCBOR())
        }

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
