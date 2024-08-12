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
package eu.europa.ec.eudi.pidissuer.adapter.out.persistence

import eu.europa.ec.eudi.pidissuer.domain.WalletAttestationNonce
import eu.europa.ec.eudi.pidissuer.domain.isExpired
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Clock
import java.time.Duration
import java.util.UUID

class InMemoryWalletAttestationNonceRepository(
    private val clock: Clock,
    private val expirationDuration: Duration = Duration.ofMinutes(5),
    private val data: MutableMap<String, WalletAttestationNonce> = mutableMapOf(),
) {

    private val mutex = Mutex()

    suspend fun deleteExpiredNonces() {
        mutex.withLock(this) {
            data.removeIfValue { it.isExpired(clock.instant()) }
        }
    }

    suspend fun checkNonceValid(nonce: String): Boolean = mutex.withLock(this) {
        data[nonce]?.isExpired(clock.instant())?.not() ?: false
    }

    suspend fun new(): WalletAttestationNonce = mutex.withLock(this) {
        val nonce = WalletAttestationNonce(
            UUID.randomUUID().toString(),
            clock.instant(),
            expirationDuration
        )
        data[nonce.nonce] = nonce
        nonce
    }

    internal suspend fun clear(): Unit =
        mutex.withLock(this) {
            data.clear()
        }
}

fun <K, V> MutableMap<K, V>.removeIfValue(predicate: (V) -> Boolean) =
    filterValues(predicate).forEach { (k, _) -> remove(k) }
