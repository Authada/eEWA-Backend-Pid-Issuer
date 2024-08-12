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
package eu.europa.ec.eudi.pidissuer.domain.tlv

import com.nimbusds.jose.JWSHeader
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.Pid
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.PidMetaData
import eu.europa.ec.eudi.pidissuer.domain.tlv.Tag.HEADER_X5CERT
import org.bouncycastle.util.Arrays
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.time.LocalDate

private fun ByteArrayOutputStream.write(tag: Tag, data: String) =
    this.write(tag, data.toByteArray(Charsets.UTF_8))


private fun ByteArrayOutputStream.write(tag: Tag, data: ByteArray) {
    this.writeBytes(buildTlv(tag, data))
}

fun buildTlv(tag: Tag, data: ByteArray): ByteArray {
    return buildTlv(tag, data.size.toShort(), data)
}

private fun buildTlv(tag: Tag, length: Short, data: ByteArray): ByteArray {
    val buffer = ByteBuffer.allocate(Short.SIZE_BYTES * 2 + data.size)
    buffer.putShort(tag.value.toShort())
    buffer.putShort(length)
    buffer.put(data)
    return buffer.array()
}

object PIDTLVPayload {
    fun mapPid(pid: Pid, pidMetaData: PidMetaData): List<Pair<Tag, String>> = setOf(
        Tag.PAYLOAD_GIVEN_NAME to pid.givenName?.value,
        Tag.PAYLOAD_FAMILY_NAME to pid.familyName?.value,
        Tag.PAYLOAD_DATE_OF_BIRTH to pid.birthDate?.toEUFormat(),
        Tag.PAYLOAD_SOURCE_DOCUMENT_TYPE to pidMetaData.sourceType,
        Tag.PAYLOAD_DATE_OF_EXPIRY to pidMetaData.expiryDate?.toEUFormat(),
//        Tag.PAYLOAD_ACADEMIC_TITLE to pid.alsoKnownAs, //TODO no pid field
        Tag.PAYLOAD_RESIDENCE_STREET_ADDRESS to pid.residentStreet?.value,
        Tag.PAYLOAD_RESIDENCE_LOCALITY to pid.residentCity?.value,
        Tag.PAYLOAD_RESIDENCE_POSTAL_CODE to pid.residentPostalCode?.value,
        Tag.PAYLOAD_RESIDENCE_COUNTRY to pid.residentCountry?.value,
        Tag.PAYLOAD_NATIONALITY to pid.nationality?.value,
        Tag.PAYLOAD_BIRTH_NAME to pid.familyNameBirth?.value,
        Tag.PAYLOAD_BIRTH_LOCALITY to pid.birthPlace,
        Tag.PAYLOAD_ALSO_KNOWN_AS to pid.alsoKnownAs,
    ).map { (first, second) -> second?.let { first to second } }
        .filterNotNull()
        .toSet()
        .sortedBy { it.first.value }

    operator fun invoke(pid: Pid, pidMetaData: PidMetaData): ByteArray {
        val output = ByteArrayOutputStream().apply {
            mapPid(pid, pidMetaData).forEach {
                write(it.first, it.second)
            }
        }
        return output.toByteArray()

    }
}

fun JWSHeader.toSeTlv(): ByteArray {
    val output = ByteArrayOutputStream().apply {
        write(
            Tag.HEADER_KEY,
            this@toSeTlv.jwk!!.toECKey().let { Arrays.concatenate(byteArrayOf(0x04), it.x.decode(), it.y.decode()) })
        write(Tag.HEADER_X5C, byteArrayOf(x509CertChain.size.toByte()) + Arrays.concatenate(x509CertChain.map {
            buildTlv(
                HEADER_X5CERT,
                it.decode()
            )
        }.toTypedArray<ByteArray>()))
    }
    return output.toByteArray()
}


fun LocalDate.toEUFormat(): String = "${year}-${monthValue}-${dayOfMonth}"
