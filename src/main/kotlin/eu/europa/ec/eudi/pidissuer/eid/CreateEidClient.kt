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
package eu.europa.ec.eudi.pidissuer.eid

import de.bund.bsi.eid.EID
import de.bund.bsi.eid.EID_Service
import jakarta.xml.ws.BindingProvider
import org.apache.cxf.configuration.jsse.TLSClientParameters
import org.apache.cxf.endpoint.Client
import org.apache.cxf.frontend.ClientProxy
import org.apache.cxf.transport.http.HTTPConduit
import org.apache.cxf.transports.http.configuration.ConnectionType.KEEP_ALIVE
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy
import org.apache.http.conn.ssl.DefaultHostnameVerifier
import org.apache.http.conn.util.PublicSuffixMatcherLoader
import org.apache.wss4j.common.crypto.Merlin
import java.net.URL
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory

fun createEidClient(eidConfiguration: EIDConfiguration): EID = with(eidConfiguration) {
    if (eidConfiguration.mock.not()) {
        EID_Service().getEIDSOAP().apply {
            configurate()
        }
    } else {
        EidMock()
    }
}

data class EIDConfiguration(
    val trustStore: KeyStore,
    val keyStore: KeyStore,
    val clientAlias: String,
    val keyPassword: String,
    val endpointAddress: URL,
    val mock: Boolean
)


context(EIDConfiguration)
fun EID.configurate() {
    this.configureEndpoint()
    configureInterceptors()
    configurateHttpConduit()
}

context(EIDConfiguration)
fun EID.configureEndpoint() {
    (this as BindingProvider)
        .requestContext[BindingProvider.ENDPOINT_ADDRESS_PROPERTY] = "$endpointAddress"
}

context(EIDConfiguration)
private fun EID.configureInterceptors() {
    val merlin = Merlin()
    merlin.keyStore = keyStore
    merlin.trustStore = trustStore
    val client = ClientProxy.getClient(this)
    removeUnusedInterceptors(client)
    client.inInterceptors.add(initInInterceptor(merlin))
    client.outInterceptors.add(initOutInterceptor(merlin, clientAlias, keyPassword))
}

private fun removeUnusedInterceptors(client: Client) {
    client.bus.inInterceptors.clear()
    client.bus.inFaultInterceptors.clear()
    client.bus.outInterceptors.clear()
    client.bus.outFaultInterceptors.clear()
    client.inInterceptors.clear()
    client.inFaultInterceptors.clear()
    client.outInterceptors.clear()
    client.outFaultInterceptors.clear()
}

context(EIDConfiguration)
private fun EID.configurateHttpConduit() {
    val http = ClientProxy.getClient(this).conduit as HTTPConduit
    val hcp = HTTPClientPolicy()
    val tcp = TLSClientParameters()
    hcp.configurateHttpClient()
    tcp.configurateTlsClientParameters()
    http.client = hcp
    http.tlsClientParameters = tcp
}


private fun HTTPClientPolicy.configurateHttpClient() {
    connectionTimeout = 10000
    receiveTimeout = 10000
    connection = KEEP_ALIVE
    isAllowChunking = false
    isAutoRedirect = false
}

context(EIDConfiguration)
private fun TLSClientParameters.configurateTlsClientParameters() {
    isUseHttpsURLConnectionDefaultSslSocketFactory = false
    isUseHttpsURLConnectionDefaultHostnameVerifier = false
    isDisableCNCheck = false
    hostnameVerifier = DefaultHostnameVerifier(PublicSuffixMatcherLoader.getDefault())
    secureSocketProtocol = "TLSv1.2"
    initKeyManager()
    initTrustManager()
}


context(EIDConfiguration)
private fun TLSClientParameters.initKeyManager() {
    val keyFactory = KeyManagerFactory.getInstance(
        KeyManagerFactory.getDefaultAlgorithm()
    )

    keyFactory.init(keyStore, keyPassword.toCharArray())
    keyManagers = keyFactory.keyManagers
    certAlias = clientAlias.lowercase()
}


context(EIDConfiguration)
private fun TLSClientParameters.initTrustManager() {
    val trustFactory = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
    )
    trustFactory.init(trustStore)
    trustManagers = trustFactory.trustManagers
}


private fun initOutInterceptor(merlin: Merlin, alias: String, password: String?): OutInterceptor {
    return OutInterceptor(
        alias,
        password,
        merlin
    )
}


private fun initInInterceptor(merlin: Merlin): InInterceptor = InInterceptor(merlin)
