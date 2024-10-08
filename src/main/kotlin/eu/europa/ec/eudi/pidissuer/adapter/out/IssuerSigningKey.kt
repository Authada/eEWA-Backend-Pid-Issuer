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
package eu.europa.ec.eudi.pidissuer.adapter.out

import COSE.AlgorithmID
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertChainUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.AuthenticatedChannelAlgorithmID
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.AuthenticatedChannelSigner
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider

@JvmInline
value class IssuerSigningKey(val key: ECKey) {
    init {
        require(key.isPrivate) { "a private key is required for signing" }
        require(!key.keyID.isNullOrBlank()) { "issuer key must have kid" }
        require(!key.x509CertChain.isNullOrEmpty()) { "issuer key must have an x5c certificate chain" }
    }
}

internal val IssuerSigningKey.signingAlgorithm: JWSAlgorithm
    get() = when (val curve = key.curve) {
        Curve.P_256 -> JWSAlgorithm.ES256
        Curve.P_384 -> JWSAlgorithm.ES384
        Curve.P_521 -> JWSAlgorithm.ES512
        else -> error("Unsupported ECKey Curve '$curve'")
    }


internal val IssuerSigningKey.authenticatedChannelAlgorithm: JWSAlgorithm
    get() = when (val curve = key.curve) {
        Curve.P_256 -> AuthenticatedChannelSigner.P256_ALGID
        Curve.P_384 -> AuthenticatedChannelSigner.P384_ALGID
        Curve.P_521 -> AuthenticatedChannelSigner.P512_ALGID
        else -> error("Unsupported ECKey Curve '$curve'")
    }

internal val IssuerSigningKey.algorithmId: AlgorithmID
    get() = when (val curve = key.curve) {
        Curve.P_256 -> AlgorithmID.ECDSA_256
        Curve.P_384 -> AlgorithmID.ECDSA_384
        Curve.P_521 -> AlgorithmID.ECDSA_512
        else -> error("Unsupported ECKey Curve '$curve'")
    }

internal val IssuerSigningKey.authenticatedChannelAlgorithmId: AuthenticatedChannelAlgorithmID
    get() = when (val curve = key.curve) {
        Curve.P_256 -> AuthenticatedChannelAlgorithmID.`DVS-P256-SHA256-HS256`
        Curve.P_384 -> AuthenticatedChannelAlgorithmID.`DVS-P384-SHA256-HS256`
        Curve.P_521 -> AuthenticatedChannelAlgorithmID.`DVS-P512-SHA256-HS256`
        else -> error("Unsupported ECKey Curve '$curve'")
    }

internal fun IssuerSigningKey.cryptoProvider(): SimpleCOSECryptoProvider {
    return SimpleCOSECryptoProvider(
        listOf(
            COSECryptoProviderKeyInfo(
                keyID = key.keyID,
                algorithmID = algorithmId,
                publicKey = key.toECPublicKey(),
                privateKey = key.toECPrivateKey(),
                x5Chain = X509CertChainUtils.parse(key.x509CertChain),
                trustedRootCAs = emptyList(),
            ),
        ),
    )
}
