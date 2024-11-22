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
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation
import eu.europa.ec.eudi.pidissuer.adapter.input.web.TokenApi
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.parseDer
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryWalletAttestationNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.removeIfValue
import eu.europa.ec.eudi.pidissuer.domain.CredentialKey.DIDUrl
import eu.europa.ec.eudi.pidissuer.domain.CredentialKey.Jwk
import eu.europa.ec.eudi.pidissuer.domain.CredentialKey.X5c
import eu.europa.ec.eudi.pidissuer.domain.WAVError.Invalid
import eu.europa.ec.eudi.pidissuer.port.input.ClientId
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.bouncycastle.openssl.X509TrustedCertificateBlock
import org.opensaml.security.x509.impl.CertPathPKIXTrustEvaluator
import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit

sealed interface WAVError {
    object Invalid : WAVError
}
private val log = LoggerFactory.getLogger(ValidateWalletAttestation::class.java)

class ValidateWalletAttestation(
    private val inMemoryWalletAttestationNonceRepository: InMemoryWalletAttestationNonceRepository,
    private val clock: Clock,
    private val walletProviderTrustStore: KeyStore
) {

    private val knownAttestations: MutableMap<String, Instant> = mutableMapOf()
    private val mutex = Mutex()


    context(Raise<WAVError>)
    suspend operator fun invoke(
        clientId: ClientId,
        issuerId: CredentialIssuerId,
        unvalidatedAttestation: SignedJWT,
        unvalidatedAttestationPop: SignedJWT,
    ) {
        val (issuer, cnfJwk) = validateWalletProviderAttestation(unvalidatedAttestation.header)
        val attestationClaims = getAttestationClaims(clientId, unvalidatedAttestation, issuer, cnfJwk)
        val cnfMap: MutableMap<String, Any> = attestationClaims!!.getJSONObjectClaim("cnf")
        @Suppress("UNCHECKED_CAST") val cnfKey = JWK.parse(cnfMap.get("jwk") as Map<String, *>)

        val attestationPopClaims = getAttestationPopClaims(clientId, issuerId, unvalidatedAttestationPop, cnfKey)
        val nonce = attestationPopClaims!!.getStringClaim("nonce")
        val jtiValid = mutex.withLock(this) {
            val valid = knownAttestations.get(
                attestationPopClaims.jwtid,
            )?.takeIf { it.isAfter(clock.instant()) } == null
            if (valid) {
                knownAttestations.put(attestationPopClaims.jwtid, attestationClaims.expirationTime.toInstant())
            }
            valid
        }
        ensure(
            nonce != null &&
                    inMemoryWalletAttestationNonceRepository.checkNonceValid(nonce) &&
                    jtiValid
        ) {
            raise(Invalid)
        }
    }

    context(Raise<WAVError>)
    private fun validateWalletProviderAttestation(header: JWSHeader): Pair<String, JWK> {
        val walletProviderAttestationJwt = SignedJWT.parse(header.getCustomParam("jwt") as String)
        val (alg, key) = algorithmAndCredentialKey(
            walletProviderAttestationJwt.header,
            JWSAlgorithm.Family.SIGNATURE.toNonEmptySetOrNull()!!
        )

        val chain = when (key) {
            is DIDUrl -> X509CertChainUtils.parse(key.jwk.x509CertChain)
            is Jwk -> X509CertChainUtils.parse(key.value.x509CertChain)
            is X5c -> key.chain
        }

        try {
            val certPath = CertificateFactory.getInstance("X509").generateCertPath(chain)
            val cpv = CertPathValidator.getInstance("PKIX")
            cpv.validate(certPath, PKIXParameters(walletProviderTrustStore).apply {
                isRevocationEnabled = false
            })
        } catch (e: Exception) {
            log.error("Certpath validation failed", e)
            raise(Invalid)
        }

        val claims = DefaultJWTProcessor<SecurityContext>()
            .apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType("wallet-provider-attestation+jwt"))
                jwsKeySelector = keySelector(key, alg)
                jwtClaimsSetVerifier =
                    DefaultJWTClaimsVerifier<SecurityContext?>(
                        JWTClaimsSet.Builder()
                            .issuer("AUTHADA")
                            .build(),
                        setOf(
                            JWTClaimNames.ISSUER,
                            JWTClaimNames.SUBJECT,
                            JWTClaimNames.ISSUED_AT,
                            JWTClaimNames.EXPIRATION_TIME,
                            "cnf",
                        ),
                    ).apply {
                        maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                    }
            }.process(walletProviderAttestationJwt, null)

        @Suppress("UNCHECKED_CAST")
        return Pair(claims.subject, JWK.parse(claims.getJSONObjectClaim("cnf").get("jwk") as Map<String, Any>))
    }

    suspend fun clearExpired() {
        val now = clock.instant()
        mutex.withLock(this) {
            knownAttestations.removeIfValue { it.isAfter(now) }
        }
    }
}


context(Raise<WAVError>)
private fun getAttestationClaims(clientId: ClientId, signedJwt: SignedJWT, issuer: String, cnfJwk: JWK): JWTClaimsSet? {
    val (algorithm, credentialKey) = algorithmAndCredentialKey(signedJwt.header, nonEmptySetOf(JWSAlgorithm.ES256))
    validateAttestationJwk(credentialKey, cnfJwk)
    val keySelector = keySelector(credentialKey, algorithm)
    val processor = attestationProcessor(clientId, issuer, keySelector)
    return processor.process(signedJwt, null)
}

context(Raise<WAVError>)
private fun validateAttestationJwk(
    credentialKey: CredentialKey,
    cnfJwk: JWK
) {
    val attestationJwk = when (credentialKey) {
        is DIDUrl -> credentialKey.jwk.toPublicJWK()
        is Jwk -> credentialKey.value.toPublicJWK()
        is X5c -> JWK.parse(credentialKey.certificate).toPublicJWK()
    }

    ensure(attestationJwk.computeThumbprint().equals(cnfJwk.computeThumbprint())) {
        raise(Invalid)
    }
}

private fun getAttestationPopClaims(
    clientId: ClientId,
    issuerId: CredentialIssuerId,
    signedJwt: SignedJWT,
    cnf: JWK
): JWTClaimsSet? {
    if (signedJwt.header.algorithm != JWSAlgorithm.ES256) {
        error("signing algorithm '${signedJwt.header.algorithm.name}' is not supported only ES256 supported")
    }
    val processor = attestationPopProcessor(
        issuerId,
        clientId,
        SingleKeyJWSKeySelector(JWSAlgorithm.ES256, cnf.toECKey().toECPublicKey())
    )
    return processor.process(signedJwt, null)
}


fun algorithmAndCredentialKey(
    header: JWSHeader,
    supported: NonEmptySet<JWSAlgorithm>,
): Pair<JWSAlgorithm, CredentialKey> {
    val algorithm = header.algorithm
        .takeIf(JWSAlgorithm.Family.SIGNATURE::contains)
        ?.takeIf(supported::contains)
        ?: error("signing algorithm '${header.algorithm.name}' is not supported")

    val kid = header.keyID
    val jwk = header.jwk
    val x5c = header.x509CertChain

    val key = when {
        kid != null && jwk == null && x5c.isNullOrEmpty() -> DIDUrl(kid).getOrThrow()
        kid == null && jwk != null && x5c.isNullOrEmpty() -> Jwk(jwk)
        kid == null && jwk == null && !x5c.isNullOrEmpty() -> X5c.parseDer(x5c).getOrThrow()

        else -> error("a public key must be provided in one of 'kid', 'jwk', or 'x5c'")
    }.apply { ensureCompatibleWith(algorithm) }

    return (algorithm to key)
}

private fun CredentialKey.ensureCompatibleWith(algorithm: JWSAlgorithm) {
    fun JWK.ensureCompatibleWith(algorithm: JWSAlgorithm) {
        val supportedAlgorithms =
            when (this) {
                is RSAKey -> RSASSASigner.SUPPORTED_ALGORITHMS
                is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                is OctetKeyPair -> Ed25519Signer.SUPPORTED_ALGORITHMS
                else -> error("unsupported key type '${keyType.value}'")
            }
        require(algorithm in supportedAlgorithms) {
            "key type '${keyType.value}' is not compatible with signing algorithm '${algorithm.name}'"
        }
    }

    when (this) {
        is DIDUrl -> jwk.ensureCompatibleWith(algorithm)
        is Jwk -> value.ensureCompatibleWith(algorithm)

        is X5c -> {
            val supportedAlgorithms =
                when (certificate.publicKey) {
                    is RSAPublicKey -> RSASSASigner.SUPPORTED_ALGORITHMS
                    is ECPublicKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                    is EdECPublicKey -> Ed25519Signer.SUPPORTED_ALGORITHMS
                    else -> error("unsupported certificate algorithm '${certificate.publicKey.algorithm}'")
                }
            require(algorithm in supportedAlgorithms) {
                "certificate algorithm '${certificate.publicKey.algorithm}' is not compatible with signing algorithm '${algorithm.name}'"
            }
        }
    }
}

private fun keySelector(
    credentialKey: CredentialKey,
    algorithm: JWSAlgorithm,
): JWSKeySelector<SecurityContext> {
    fun <C : SecurityContext> JWK.keySelector(algorithm: JWSAlgorithm): SingleKeyJWSKeySelector<C> =
        when (this) {
            is AsymmetricJWK -> SingleKeyJWSKeySelector(algorithm, toPublicKey())
            else -> TODO("CredentialKey.Jwk with non AsymmetricJWK is not yet supported")
        }

    return when (credentialKey) {
        is DIDUrl -> credentialKey.jwk.keySelector(algorithm)
        is Jwk -> credentialKey.value.keySelector(algorithm)
        is X5c -> SingleKeyJWSKeySelector(algorithm, credentialKey.certificate.publicKey)
    }
}

private val maxSkew = 30.seconds

private val attestationType = JOSEObjectType("wallet-attestation+jwt")
private fun attestationProcessor(
    clientId: String,
    issuer: String,
    keySelector: JWSKeySelector<SecurityContext>,
): JWTProcessor<SecurityContext> =
    DefaultJWTProcessor<SecurityContext>()
        .apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(attestationType)
            jwsKeySelector = keySelector
            jwtClaimsSetVerifier =
                DefaultJWTClaimsVerifier<SecurityContext?>(
                    JWTClaimsSet.Builder()
                        .claim("aal", "https://trust-list.eu/aal/high") //TODO align this value
                        .subject(clientId)
                        .issuer(issuer)
                        .build(),
                    setOf(
                        JWTClaimNames.ISSUER,
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        "cnf",
                        "aal",
                    ),
                ).apply {
                    maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                }
        }

private fun attestationPopProcessor(
    issuerId: CredentialIssuerId,
    clientId: ClientId,
    keySelector: JWSKeySelector<SecurityContext>,
): JWTProcessor<SecurityContext> =
    DefaultJWTProcessor<SecurityContext>()
        .apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier()
            jwsKeySelector = keySelector
            jwtClaimsSetVerifier =
                DefaultJWTClaimsVerifier<SecurityContext?>(
                    issuerId, // aud
                    JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .build(),
                    setOf(
                        JWTClaimNames.JWT_ID,
                        JWTClaimNames.AUDIENCE,
                        JWTClaimNames.EXPIRATION_TIME,
                        JWTClaimNames.ISSUER,
                    ),
                ).apply {
                    maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                }
        }
