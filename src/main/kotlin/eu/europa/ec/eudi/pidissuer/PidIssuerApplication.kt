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
package eu.europa.ec.eudi.pidissuer

import arrow.core.NonEmptySet
import arrow.core.recover
import arrow.core.some
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import eu.europa.ec.eudi.pidissuer.adapter.input.web.AuthorizationRequestApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.EidApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.PushedAuthorizationRequestApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.TokenApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPLocalIntrospector
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPTokenReactiveAuthenticationManager
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPTokenServerAccessDeniedHandler
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPTokenServerAuthenticationEntryPoint
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.ServerDPoPAuthenticationTokenAuthenticationConverter
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.authenticatedChannelAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.CredentialRequestFactory
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.DefaultResolveCredentialRequestByCredentialIdentifier
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.DefaultExtractJwkFromCredentialKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.EncryptCredentialResponseNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.EncryptDeferredResponseNimbus
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DefaultEncodeMobileDrivingLicenceInCbor
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.EncodeMobileDrivingLicenceInCbor
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.GetMobileDrivingLicenceDataMock
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.IssueMobileDrivingLicence
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.MobileDrivingLicenceV1
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.MobileDrivingLicenceV1Scope
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryAuthorizationRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryCNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryDeferredCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryIssuedCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryWalletAttestationNonceRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.AuthenticatedChannelCertificateIssuer
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.DefaultEncodePidInCbor
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.EncodePidInCbor
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.GetLocalPidData
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.IssueMsoMdocPid
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.IssueSdJwtVcPid
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.IssueSeTlvVcPidWithCertificate
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocScope
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMsoMdocV1
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidSdJwtVcV1
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.pidSeTlvVcV1WithCertificate
import eu.europa.ec.eudi.pidissuer.adapter.out.qr.DefaultGenerateQrCode
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.CredentialIdentifier
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponseEncryption
import eu.europa.ec.eudi.pidissuer.domain.CredentialResponseEncryptionSupportedParameters
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.domain.MsoMdocCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.SeTlvVcCredentialRequest
import eu.europa.ec.eudi.pidissuer.domain.ValidateWalletAttestation
import eu.europa.ec.eudi.pidissuer.eid.EIDConfiguration
import eu.europa.ec.eudi.pidissuer.eid.createEidClient
import eu.europa.ec.eudi.pidissuer.port.input.AccessTokenRequest
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationRequest
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.input.CreateTCToken
import eu.europa.ec.eudi.pidissuer.port.input.GetAuthorizationMetaData
import eu.europa.ec.eudi.pidissuer.port.input.GetCredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.port.input.GetDeferredCredential
import eu.europa.ec.eudi.pidissuer.port.input.HandleEidResult
import eu.europa.ec.eudi.pidissuer.port.input.HandleNotificationRequest
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredential
import eu.europa.ec.eudi.pidissuer.port.input.PushedAuthorizationRequest
import eu.europa.ec.eudi.pidissuer.port.input.WalletClientAttestation
import eu.europa.ec.eudi.pidissuer.port.out.asDeferred
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateCNonce
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import jakarta.ws.rs.client.Client
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.TrustAllStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.keycloak.admin.client.spi.ResteasyClientClassicProvider
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.boot.web.codec.CodecCustomizer
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.GenericApplicationContext
import org.springframework.context.support.beans
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.env.getRequiredProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.FileSystemResource
import org.springframework.core.io.Resource
import org.springframework.http.HttpStatus
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenReactiveAuthenticationManager
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.AuthenticationConverterServerWebExchangeMatcher
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import reactor.netty.http.client.HttpClient
import java.io.File
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.util.Date
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration
import kotlin.time.toKotlinDuration

private val log = LoggerFactory.getLogger(PidIssuerApplication::class.java)

/**
 * [WebClient] instances for usage within the application.
 */
internal object WebClients {

    /**
     * A [WebClient] with [Json] serialization enabled.
     */
    val Default: WebClient by lazy {
        val json = Json { ignoreUnknownKeys = true }
        WebClient
            .builder()
            .codecs {
                it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
                it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
                it.defaultCodecs().enableLoggingRequestDetails(true)
            }
            .build()
    }

    /**
     * A [WebClient] with [Json] serialization enabled that trusts *all* certificates.
     */
    val Insecure: WebClient by lazy {
        log.warn("Using insecure WebClient trusting all certificates")
        val sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        val httpClient = HttpClient.create().secure { it.sslContext(sslContext) }
        Default.mutate()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .build()
    }
}

/**
 * [Client] instances for usage within the application.
 */
internal object RestEasyClients {

    /**
     * A [Client].
     */
    val Default: Client by lazy {
        ResteasyClientClassicProvider().newRestEasyClient(null, null, false)
    }

    /**
     * A [Client] that trusts *all* certificates.
     */
    val Insecure: Client by lazy {
        log.warn("Using insecure RestEasy Client trusting all certificates")
        val sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(TrustAllStrategy())
            .build()
        ResteasyClientClassicProvider().newRestEasyClient(null, sslContext, true)
    }
}

@OptIn(ExperimentalSerializationApi::class)
fun beans(clock: Clock) = beans {
    val issuerPublicUrl = env.readRequiredUrl("issuer.publicUrl", removeTrailingSlash = true)
    val enableMobileDrivingLicence = env.getProperty("issuer.mdl.enabled", true)
    val enableMsoMdocPid = env.getProperty<Boolean>("issuer.pid.mso_mdoc.enabled") ?: true
    val enableSdJwtVcPid = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.enabled") ?: true
    val enableSeTlvVcPidWithCertificate =
        env.getProperty<Boolean>("issuer.pid.se_tlv_vc.enabled") ?: true
    val credentialsOfferUri = env.getRequiredProperty("issuer.credentialOffer.uri")

    //
    // Signing key
    //

    bean(isLazyInit = true) {
        val signingKey = when (env.getProperty<KeyOption>("issuer.signing-key")) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random signing key and self-signed certificate for issuance")
                val key = ECKeyGenerator(Curve.P_256).keyID("issuer-kid-0").generate()
                val certificate = X509CertificateUtils.generateSelfSigned(
                    Issuer(issuerPublicUrl.value.host),
                    Date.from(clock.instant()),
                    Date.from(clock.instant() + 365.days.toJavaDuration()),
                    key.toECPublicKey(),
                    key.toECPrivateKey(),
                )
                ECKey.Builder(key)
                    .x509CertChain(listOf(Base64.encode(certificate.encoded)))
                    .build()
            }

            KeyOption.LoadFromKeystore -> {
                log.info("Loading signing key and certificate for issuance from keystore")
                loadJwkFromKeystore(env, "issuer.signing-key")
            }
        }
        require(signingKey is ECKey) { "Only ECKeys are supported for signing" }
        IssuerSigningKey(signingKey)
    }

    //
    // Adapters (out ports)
    //
    bean { clock }
    bean {
        if ("insecure" in env.activeProfiles) {
            WebClients.Insecure
        } else {
            WebClients.Default
        }
    }
    bean {
        if ("insecure" in env.activeProfiles) {
            RestEasyClients.Insecure
        } else {
            RestEasyClients.Default
        }
    }
    bean {
        GetLocalPidData(ref(), clock)
    }
    bean<EncodePidInCbor>(isLazyInit = true) {
        when (env.getProperty<MsoMdocEncoderOption>("issuer.pid.mso_mdoc.encoder")) {
            null, MsoMdocEncoderOption.Internal -> {
                log.info("Using internal encoder to encode PID in CBOR")
                val issuerSigningKey = ref<IssuerSigningKey>()
                val duration = env.getProperty("issuer.pid.mso_mdoc.encoder.duration")
                    ?.let { Duration.parse(it).toKotlinDuration() }
                    ?: 30.days
                DefaultEncodePidInCbor(clock, issuerSigningKey, duration)
            }
        }
    }
    bean {
        GetMobileDrivingLicenceDataMock()
    }
    bean<EncodeMobileDrivingLicenceInCbor>(isLazyInit = true) {
        when (env.getProperty<MsoMdocEncoderOption>("issuer.mdl.mso_mdoc.encoder")) {
            null, MsoMdocEncoderOption.Internal -> {
                log.info("Using internal encoder to encode mDL in CBOR")
                val issuerSigningKey = ref<IssuerSigningKey>()
                val duration = env.getProperty("issuer.mdl.mso_mdoc.encoder.duration")
                    ?.let { Duration.parse(it).toKotlinDuration() }
                    ?: 5.days
                DefaultEncodeMobileDrivingLicenceInCbor(clock, issuerSigningKey, duration)
            }
        }
    }
    bean(::DefaultGenerateQrCode)
    bean(::HandleNotificationRequest)
    bean {
        val resolvers = buildMap<CredentialIdentifier, CredentialRequestFactory> {
            if (enableMobileDrivingLicence) {
                this[CredentialIdentifier(MobileDrivingLicenceV1Scope.value)] =
                    { unvalidatedProof, requestedResponseEncryption, verifierKA ->
                        MsoMdocCredentialRequest(
                            unvalidatedProof = unvalidatedProof,
                            credentialResponseEncryption = requestedResponseEncryption,
                            docType = MobileDrivingLicenceV1.docType,
                            claims = MobileDrivingLicenceV1.msoClaims.mapValues { entry ->
                                entry.value.map { attribute -> attribute.name }
                            },
                            verifierKA,
                        )
                    }
            }

            if (enableMsoMdocPid) {
                this[CredentialIdentifier(PidMsoMdocScope.value)] =
                    { unvalidatedProof, requestedResponseEncryption, verifierKA ->
                        MsoMdocCredentialRequest(
                            unvalidatedProof = unvalidatedProof,
                            credentialResponseEncryption = requestedResponseEncryption,
                            docType = PidMsoMdocV1.docType,
                            claims = PidMsoMdocV1.msoClaims.mapValues { entry -> entry.value.map { attribute -> attribute.name } },
                            verifierKA
                        )
                    }
            }

            if (enableSdJwtVcPid) {
                val signingAlgorithm = ref<IssuerSigningKey>().signingAlgorithm
                pidSdJwtVcV1(signingAlgorithm).let { sdJwtVcPid ->
                    this[CredentialIdentifier(sdJwtVcPid.scope!!.value)] =
                        { unvalidatedProof, requestedResponseEncryption, verifierKA ->
                            SdJwtVcCredentialRequest(
                                unvalidatedProof = unvalidatedProof,
                                credentialResponseEncryption = requestedResponseEncryption,
                                type = sdJwtVcPid.type,
                                claims = sdJwtVcPid.claims.map { it.name }.toSet(),
                                verifierKA,
                            )
                        }
                }
            }

            if (enableSeTlvVcPidWithCertificate) {
                val signingAlgorithm = ref<IssuerSigningKey>().authenticatedChannelAlgorithm
                pidSeTlvVcV1WithCertificate(signingAlgorithm).let { seTlvVC ->
                    this[CredentialIdentifier(seTlvVC.scope!!.value)] =
                        { unvalidatedProof, requestedResponseEncryption, verifierKA ->
                            SeTlvVcCredentialRequest(
                                unvalidatedProof = unvalidatedProof,
                                credentialResponseEncryption = requestedResponseEncryption,
                                type = seTlvVC.type,
                                claims = seTlvVC.claims.map { it.name }.toSet(),
                                verifierKA,
                            )
                        }
                }
            }
        }

        DefaultResolveCredentialRequestByCredentialIdentifier(resolvers)
    }

    bean {
        CleanupScheduler(ref(), ref(), ref(), clock)
    }

    //
    // Encryption of credential response
    //
    bean(isLazyInit = true) {
        EncryptDeferredResponseNimbus(ref<CredentialIssuerMetaData>().id, clock)
    }
    bean(isLazyInit = true) {
        EncryptCredentialResponseNimbus(ref<CredentialIssuerMetaData>().id, clock)
    }

    with(InMemoryAuthorizationRepository()) {
        bean { GetAuthorizationSession }
        bean { StoreAuthorizationSession }
        bean { GetAccessTokenMetadataByToken }
        bean { StoreAccessTokenMetadataByToken }
        bean { StoreRequestUriReference }
        bean { GetAuthorizationSessionByRequestUriOnce }
        bean { GetAuthorizationSessionByRequestUriRepeatable }
    }
    //
    // CNonce
    //
    with(InMemoryCNonceRepository()) {
        bean { deleteExpiredCNonce }
        bean { upsertCNonce }
        bean { loadCNonceByAccessToken }
        bean { GenerateCNonce.random(Duration.ofMinutes(5L)) }
        bean { this@with } // this is needed for test
    }

    //
    // Credentials
    //
    with(InMemoryIssuedCredentialRepository()) {
        bean { GenerateNotificationId.Random }
        bean { storeIssuedCredential }
        bean { loadIssuedCredentialByNotificationId }
    }

    //
    // Deferred Credentials
    //
    with(InMemoryDeferredCredentialRepository(mutableMapOf())) {
        bean { GenerateTransactionId.Random }
        bean { storeDeferredCredential }
        bean { loadDeferredCredentialByTransactionId }
    }
    bean {
        val expiration = env.getRequiredProperty("issuer.pid.se_tlv_vc.expiration").let {
            runCatching {
                Duration.parse(it).takeUnless { it.isZero || it.isNegative }
            }.getOrThrow()
        }
        AuthenticatedChannelCertificateIssuer(clock, ref(), { iat -> iat.plus(expiration).toInstant() })
    }

    //
    // Specific Issuers
    //
    bean {
        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = issuerPublicUrl.appendPath(WalletApi.CREDENTIAL_ENDPOINT),
            deferredCredentialEndpoint = issuerPublicUrl.appendPath(WalletApi.DEFERRED_ENDPOINT),
            notificationEndpoint = issuerPublicUrl.appendPath(WalletApi.NOTIFICATION_ENDPOINT),
            credentialResponseEncryption = env.credentialResponseEncryption(),
            specificCredentialIssuers = buildList {
                if (enableMsoMdocPid) {
                    val issueMsoMdocPid = IssueMsoMdocPid(
                        credentialIssuerId = issuerPublicUrl,
                        getPidData = ref(),
                        encodePidInCbor = ref(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.mso_mdoc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        clock = clock,
                        storeIssuedCredential = ref(),
                    )
                    add(issueMsoMdocPid)
                }

                val issuerSigningKey = ref<IssuerSigningKey>()
                if (enableSeTlvVcPidWithCertificate) {
                    val deferred = env.getProperty<Boolean>("issuer.pid.se_tlv_vc.deferred") ?: false

                    val issueSdJwtVcPidWithCertificate = IssueSeTlvVcPidWithCertificate(
                        issuerSigningKey = issuerSigningKey,
                        getPidData = ref(),
                        clock = clock,
                        credentialIssuerId = issuerPublicUrl,
                        extractJwkFromCredentialKey = DefaultExtractJwkFromCredentialKey,
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.se_tlv_vc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        storeIssuedCredential = ref(),
                        issuer = ref()
                    )

                    add(
                        if (deferred) issueSdJwtVcPidWithCertificate.asDeferred(ref(), ref())
                        else issueSdJwtVcPidWithCertificate,
                    )
                }

                if (enableSdJwtVcPid) {
                    val deferred = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.deferred") ?: false
                    val notUseBefore = env.getProperty("issuer.pid.sd_jwt_vc.notUseBefore")?.let {
                        runCatching {
                            Duration.parse(it).takeUnless { it.isZero || it.isNegative }
                        }.getOrNull()
                    }


                    val issueSdJwtVcPid = IssueSdJwtVcPid(
                        hashAlgorithm = HashAlgorithm.SHA_256,
                        issuerSigningKey = issuerSigningKey,
                        getPidData = ref(),
                        clock = clock,
                        credentialIssuerId = issuerPublicUrl,
                        extractJwkFromCredentialKey = DefaultExtractJwkFromCredentialKey,
                        calculateExpiresAt = { iat -> iat.plusDays(30).toInstant() },
                        calculateNotUseBefore = notUseBefore?.let { duration ->
                            { iat ->
                                iat.plusSeconds(duration.seconds).toInstant()
                            }
                        },
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.notifications.enabled")
                            ?: true,
                        generateNotificationId = ref(),
                        storeIssuedCredential = ref(),
                    )

                    add(
                        if (deferred) issueSdJwtVcPid.asDeferred(ref(), ref())
                        else issueSdJwtVcPid,
                    )

                }


                if (enableMobileDrivingLicence) {
                    val mdlIssuer = IssueMobileDrivingLicence(
                        credentialIssuerId = issuerPublicUrl,
                        getMobileDrivingLicenceData = ref(),
                        encodeMobileDrivingLicenceInCbor = ref(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.mdl.notifications.enabled") ?: true,
                        generateNotificationId = ref(),
                        clock = clock,
                        storeIssuedCredential = ref(),
                    )
                    add(mdlIssuer)
                }
            },
        )
    }

    bean {
        AuthorizationServerMetadata(
            Issuer(issuerPublicUrl.externalForm)
        ).apply {
            authorizationEndpointURI =
                issuerPublicUrl.appendPath(AuthorizationRequestApi.AUTHORIZATION_ENDPOINT).value.toURI()
            tokenEndpointURI = issuerPublicUrl.appendPath(TokenApi.TOKEN_ENDPOINT).value.toURI()
            pushedAuthorizationRequestEndpointURI =
                issuerPublicUrl.appendPath(PushedAuthorizationRequestApi.PAR_ENDPOINT).value.toURI()
            jwkSetURI = issuerPublicUrl.appendPath(MetaDataApi.WELL_KNOWN_JWKS).value.toURI()
            dPoPJWSAlgs = (JWSAlgorithm.Family.EC + JWSAlgorithm.Family.RSA).toList()
            requiresPushedAuthorizationRequests(true)
            setSupportsTLSClientCertificateBoundAccessTokens(false)
            setSupportsBackChannelUserCodeParam(false)
            setSupportsAuthorizationResponseIssuerParam(false)
            setSupportsRequestParam(false)
            setSupportsRequestURIParam(false)
            tokenEndpointAuthMethods = listOf(ClientAuthenticationMethod(WalletClientAttestation.methodName))
            grantTypes = listOf(GrantType.AUTHORIZATION_CODE)
            responseModes = listOf(ResponseMode.QUERY)
            responseTypes = listOf(ResponseType.CODE)
            this.setRequiresRequestURIRegistration(false)
            scopes =
                com.nimbusds.oauth2.sdk.Scope(*(ref<CredentialIssuerMetaData>().specificCredentialIssuers.mapNotNull { it.supportedCredential.scope?.value }).toTypedArray())
        }
    }

    //
    //EID configuration
    //
    bean {
        createEidClient(
            EIDConfiguration(
                trustStore = createKeyStore(
                    env.getRequiredProperty<String>("issuer.eid.truststore-path"),
                    env.getRequiredProperty<String>("issuer.eid.truststore-type"),
                    env.getRequiredProperty<String>("issuer.eid.truststore-password"),
                ),
                keyStore = createKeyStore(
                    env.getRequiredProperty<String>("issuer.eid.keystore-path"),
                    env.getRequiredProperty<String>("issuer.eid.keystore-type"),
                    env.getRequiredProperty<String>("issuer.eid.keystore-password"),
                ),
                clientAlias = env.getRequiredProperty<String>("issuer.eid.key-alias"),
                keyPassword = env.getRequiredProperty<String>("issuer.eid.key-password"),
                endpointAddress = env.getRequiredProperty<URL>("issuer.eid.endpoint"),
                mock = env.getRequiredProperty<Boolean>("issuer.eid.mock")
            )
        )
    }
    bean {
        InMemoryWalletAttestationNonceRepository(clock)
    }

    bean {
        ValidateWalletAttestation(ref(), clock)
    }

    //
    // In Ports (use cases)
    //
    bean {
        CreateTCToken(ref(), ref(), ref())
    }
    bean {
        PushedAuthorizationRequest(ref(), ref(), issuerPublicUrl, ref(), ref())
    }
    bean {
        AuthorizationRequest(ref(), ref())
    }
    bean {
        AccessTokenRequest(ref(), ref(), ref(), ref(), ref(), issuerPublicUrl, ref(), ref(), ref())
    }
    bean {
        HandleEidResult(ref(), ref(), ref())
    }
    bean(::GetCredentialIssuerMetaData)
    bean(::GetAuthorizationMetaData)
    bean {
        IssueCredential(clock, ref(), ref(), ref(), ref(), ref(), ref())
    }
    bean {
        GetDeferredCredential(ref(), ref())
    }
    bean {
        CreateCredentialsOffer(ref(), credentialsOfferUri)
    }

    //
    // Routes
    //
    bean {
        val metaDataApi = MetaDataApi(ref(), ref(), ref())
        val walletApi = WalletApi(ref(), ref(), ref(), ref())
        val issuerUi = IssuerUi(credentialsOfferUri, ref(), ref(), ref())
        val issuerApi = IssuerApi(ref())
        val eidApi = EidApi(ref(), ref(), issuerPublicUrl)
        val authorizationRequestApi = AuthorizationRequestApi(ref(), issuerPublicUrl)
        val tokenApi = TokenApi(ref())
        val pushedAuthorizationRequestApi = PushedAuthorizationRequestApi(ref(), ref(), ref())
        metaDataApi.route.and(walletApi.route).and(issuerUi.router).and(issuerApi.router).and(eidApi.router)
            .and(authorizationRequestApi.router).and(pushedAuthorizationRequestApi.router).and(tokenApi.router)
    }

    //
    // Security
    //
    bean {
        val algorithms = (ref<AuthorizationServerMetadata>().dPoPJWSAlgs?.toSet() ?: emptySet()).also {
            if (it.isEmpty()) log.warn("DPoP support will not be enabled. Authorization Server does not support DPoP.")
            else log.info("DPoP support will be enabled. Supported algorithms: $it")
        }
        val proofMaxAge = env.getProperty("issuer.dpop.proof-max-age", "PT1M").let { Duration.parse(it) }
        val cachePurgeInterval =
            env.getProperty("issuer.dpop.cache-purge-interval", "PT10M").let { Duration.parse(it) }
        val realm = env.getProperty("issuer.dpop.realm")?.takeIf { it.isNotBlank() }

        DPoPConfigurationProperties(algorithms, proofMaxAge, cachePurgeInterval, realm)
    }
    bean {
        /*
         * This is a Spring naming convention
         * A prefix of SCOPE_xyz will grant a SimpleAuthority(xyz)
         * if there is a scope xyz
         *
         * Note that on the OAUTH2 server we set xyz as te scope
         * and not SCOPE_xyz
         */
        val metaData = ref<CredentialIssuerMetaData>()
        val scopes = metaData.credentialConfigurationsSupported
            .mapNotNull { it.scope?.springConvention() }
            .distinct()
        val http = ref<ServerHttpSecurity>()
        http {
            authorizeExchange {
                authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.DEFERRED_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.NOTIFICATION_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(PushedAuthorizationRequestApi.PAR_ENDPOINT, permitAll)
                authorize(AuthorizationRequestApi.AUTHORIZATION_ENDPOINT, permitAll)
                authorize(EidApi.TCTOKEN_ENDPOINT, permitAll)
                authorize(EidApi.REFRESHADDRESS_ENDPOINT, permitAll)
                authorize(EidApi.COMMUNICATIONERRORADDRESS_ENDPOINT, permitAll)
                authorize(TokenApi.TOKEN_ENDPOINT, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_OAUTH_CONFIGURATION, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWKS, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWT_VC_ISSUER, permitAll)
                authorize(MetaDataApi.PUBLIC_KEYS, permitAll)
                authorize(IssuerUi.GENERATE_CREDENTIALS_OFFER, permitAll)
                authorize(IssuerApi.CREATE_CREDENTIALS_OFFER, permitAll)
                authorize("", permitAll)
                authorize("/", permitAll)
                authorize(env.getRequiredProperty("spring.webflux.static-path-pattern"), permitAll)
                authorize(env.getRequiredProperty("spring.webflux.webjars-path-pattern"), permitAll)
                authorize(anyExchange, denyAll)
            }

            csrf {
                disable()
            }

            cors {
                disable()
            }

            val dPoPProperties = ref<DPoPConfigurationProperties>()
            val enableDPoP = dPoPProperties.algorithms.isNotEmpty()

            val dPoPTokenConverter by lazy { ServerDPoPAuthenticationTokenAuthenticationConverter() }
            val dPoPEntryPoint by lazy { DPoPTokenServerAuthenticationEntryPoint(dPoPProperties.realm) }

            val bearerTokenConverter = ServerBearerTokenAuthenticationConverter()
            val bearerTokenEntryPoint = BearerTokenServerAuthenticationEntryPoint()

            exceptionHandling {
                authenticationEntryPoint = DelegatingServerAuthenticationEntryPoint(
                    buildList {
                        if (enableDPoP) {
                            add(
                                DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                                    AuthenticationConverterServerWebExchangeMatcher(dPoPTokenConverter),
                                    dPoPEntryPoint,
                                ),
                            )
                        }

                        add(
                            DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                                AuthenticationConverterServerWebExchangeMatcher(bearerTokenConverter),
                                bearerTokenEntryPoint,
                            ),
                        )
                    },
                ).apply {
                    setDefaultEntryPoint(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
                }

                accessDeniedHandler = ServerWebExchangeDelegatingServerAccessDeniedHandler(
                    buildList {
                        if (enableDPoP) {
                            ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                                AuthenticationConverterServerWebExchangeMatcher(dPoPTokenConverter),
                                DPoPTokenServerAccessDeniedHandler(dPoPProperties.realm),
                            )
                        }

                        add(
                            ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                                AuthenticationConverterServerWebExchangeMatcher(bearerTokenConverter),
                                BearerTokenServerAccessDeniedHandler(),
                            ),
                        )
                    },
                ).apply {
                    setDefaultAccessDeniedHandler(HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN))
                }
            }

            val introspector = DPoPLocalIntrospector(ref(), ref())

            if (enableDPoP) {
                val dPoPFilter = run {
                    val dPoPVerifier = DPoPProtectedResourceRequestVerifier(
                        dPoPProperties.algorithms,
                        dPoPProperties.proofMaxAge.toSeconds(),
                        DefaultDPoPSingleUseChecker(
                            dPoPProperties.proofMaxAge.toSeconds(),
                            dPoPProperties.cachePurgeInterval.toSeconds(),
                        ),
                    )

                    val authenticationManager =
                        DPoPTokenReactiveAuthenticationManager(introspector, dPoPVerifier)

                    AuthenticationWebFilter(authenticationManager).apply {
                        setServerAuthenticationConverter(ServerDPoPAuthenticationTokenAuthenticationConverter())
                        setAuthenticationFailureHandler(
                            ServerAuthenticationEntryPointFailureHandler(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)),
                        )
                    }
                }

                http.addFilterAt(dPoPFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            }

            val bearerTokenFilter = run {
                val authenticationManager = OpaqueTokenReactiveAuthenticationManager(introspector)

                AuthenticationWebFilter(authenticationManager).apply {
                    setServerAuthenticationConverter(ServerBearerTokenAuthenticationConverter())
                    setAuthenticationFailureHandler(
                        ServerAuthenticationEntryPointFailureHandler(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)),
                    )
                }
            }
            http.addFilterAfter(bearerTokenFilter, SecurityWebFiltersOrder.AUTHENTICATION)
        }
    }

    //
    // Other
    //
    bean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }
            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
}

private fun createKeyStore(location: String, type: String, password: String): KeyStore =
    KeyStore.getInstance(type).apply {
        load(File(location).inputStream(), password.toCharArray())
    }

private fun Environment.credentialResponseEncryption(): CredentialResponseEncryption {
    val isSupported = getProperty<Boolean>("issuer.credentialResponseEncryption.supported") ?: false
    return if (!isSupported) {
        CredentialResponseEncryption.NotSupported
    } else {
        val parameters = CredentialResponseEncryptionSupportedParameters(
            algorithmsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.algorithmsSupported",
                JWEAlgorithm::parse,
            ),
            methodsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.encryptionMethods",
                EncryptionMethod::parse,
            ),
        )
        val isRequired = getProperty<Boolean>("issuer.credentialResponseEncryption.required") ?: false
        if (!isRequired) {
            CredentialResponseEncryption.Optional(parameters)
        } else {
            CredentialResponseEncryption.Required(parameters)
        }
    }
}

private fun Environment.readRequiredUrl(key: String, removeTrailingSlash: Boolean = false): HttpsUrl =
    getRequiredProperty(key)
        .let { url ->
            fun String.normalize() =
                if (removeTrailingSlash) {
                    this.removeSuffix("/")
                } else {
                    this
                }

            fun String.toHttpsUrl(): HttpsUrl = HttpsUrl.of(this) ?: HttpsUrl.unsafe(this)

            url.normalize().toHttpsUrl()
        }

private fun <T> Environment.readNonEmptySet(key: String, f: (String) -> T?): NonEmptySet<T> {
    val nonEmptySet = getRequiredProperty<MutableSet<String>>(key)
        .mapNotNull(f)
        .toNonEmptySetOrNull()
    return checkNotNull(nonEmptySet) { "Missing or incorrect values values for key `$key`" }
}

private fun HttpsUrl.appendPath(path: String): HttpsUrl =
    HttpsUrl.unsafe(
        UriComponentsBuilder.fromHttpUrl(externalForm)
            .path(path)
            .build()
            .toUriString(),
    )

private const val keystoreDefaultLocation = "/keystore.jks"

/**
 * Loads a key pair alongside its associated certificate chain as a JWK.
 *
 * This method expects to find the following properties in the provided [environment].
 * - [prefix].keystore -> location of the keystore as a Spring [Resource] URL
 * - [prefix].keystore.type -> type of the keystore, e.g. JKS
 * - [prefix].keystore.password -> password used to open the keystore
 * - [prefix].alias -> alias of the key pair to load
 * - [prefix].password -> password of the key pair
 *
 * In case no keystore is found in the configured location, this methods tries to find a keystore at the location `/keystore.jks`.
 */
@Suppress("SameParameterValue")
private fun loadJwkFromKeystore(environment: Environment, prefix: String): JWK {
    fun property(property: String): String =
        when {
            prefix.isBlank() -> property
            prefix.endsWith(".") -> "$prefix$property"
            else -> "$prefix.$property"
        }

    fun JWK.withCertificateChain(chain: List<X509Certificate>): JWK {
        require(this.parsedX509CertChain.isNotEmpty()) { "jwk must have a leaf certificate" }
        require(chain.isNotEmpty()) { "chain cannot be empty" }
        require(this.parsedX509CertChain.first() == chain.first()) {
            "leaf certificate of provided chain does not match leaf certificate of jwk"
        }

        val encodedChain = chain.map { Base64.encode(it.encoded) }
        return when (this) {
            is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
            is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
            is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
            is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
            else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
        }
    }

    val keystoreResource = run {
        val keystoreLocation = environment.getRequiredProperty(property("keystore"))
        log.info("Will try to load Keystore from: '{}'", keystoreLocation)
        val keystoreResource = DefaultResourceLoader().getResource(keystoreLocation).some()
            .filter { it.exists() }
            .recover {
                log.warn(
                    "Could not find Keystore at '{}'. Fallback to '{}'",
                    keystoreLocation,
                    keystoreDefaultLocation,
                )
                FileSystemResource(keystoreDefaultLocation).some()
                    .filter { it.exists() }
                    .bind()
            }
            .getOrNull()
        checkNotNull(keystoreResource) { "Could not load Keystore either from '$keystoreLocation' or '$keystoreDefaultLocation'" }
    }

    val keystoreType = environment.getProperty(property("keystore.type"), KeyStore.getDefaultType())
    val keystorePassword = environment.getProperty(property("keystore.password"))?.takeIf { it.isNotBlank() }
    val keyAlias = environment.getRequiredProperty(property("alias"))
    val keyPassword = environment.getProperty(property("password"))?.takeIf { it.isNotBlank() }

    return keystoreResource.inputStream.use { inputStream ->
        val keystore = KeyStore.getInstance(keystoreType)
        keystore.load(inputStream, keystorePassword?.toCharArray())

        val jwk = JWK.load(keystore, keyAlias, keyPassword?.toCharArray())
        val chain = keystore.getCertificateChain(keyAlias).orEmpty()
            .map { certificate -> certificate as X509Certificate }
            .toList()

        when {
            chain.isNotEmpty() -> jwk.withCertificateChain(chain)
            else -> jwk
        }
    }
}

/**
 * Indicates whether a random key pairs should be generated, or a key pair should be loaded from a keystore.
 */
private enum class KeyOption {
    GenerateRandom,
    LoadFromKeystore,
}

/**
 * Indicates which CBOR encoder to use.
 */
private enum class MsoMdocEncoderOption {
    Internal,
}

/**
 * Configuration properties for Keycloak.
 */
data class KeycloakConfigurationProperties(
    val serverUrl: URL,
    val authenticationRealm: String,
    val clientId: String,
    val username: String,
    val password: String,
    val userRealm: String,
) {
    init {
        require(authenticationRealm.isNotBlank()) { "'authenticationRealm' cannot be blank" }
        require(clientId.isNotBlank()) { "'clientId' cannot be blank" }
        require(username.isNotBlank()) { "'username' cannot be blank" }
        require(password.isNotBlank()) { "'password' cannot be blank" }
        require(userRealm.isNotBlank()) { "'userRealm' cannot be blank" }
    }
}

fun BeanDefinitionDsl.initializer(): ApplicationContextInitializer<GenericApplicationContext> =
    ApplicationContextInitializer<GenericApplicationContext> { initialize(it) }

@SpringBootApplication
class PidIssuerApplication

fun main(args: Array<String>) {
    runApplication<PidIssuerApplication>(*args) {
        addInitializers(beans(Clock.systemDefaultZone()).initializer())
    }
}