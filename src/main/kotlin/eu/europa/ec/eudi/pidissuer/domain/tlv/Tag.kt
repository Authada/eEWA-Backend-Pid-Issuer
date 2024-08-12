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

fun payload(value: Byte): UShort {
    return (0xC000u + value.toUShort()).toUShort()
}

fun header(value: Byte): UShort {
    return (0xB000u + value.toUShort()).toUShort()
}

enum class Tag(val value: UShort) {
    HMAC(0xA001u),
    HEADER_KEY(header(0x1)),
    HEADER_X5C(header(0x2)),
    HEADER_X5CERT(header(0x3)),
    PAYLOAD_GIVEN_NAME(payload(0x1)),
    PAYLOAD_FAMILY_NAME(payload(0x2)),
    PAYLOAD_DATE_OF_BIRTH(payload(0x3)),
    PAYLOAD_SOURCE_DOCUMENT_TYPE(payload(0x4)),
    PAYLOAD_DATE_OF_EXPIRY(payload(0x5)),
    PAYLOAD_ACADEMIC_TITLE(payload(0x6)),
    PAYLOAD_RESIDENCE_STREET_ADDRESS(payload(0x7)),
    PAYLOAD_RESIDENCE_LOCALITY(payload(0x8)),
    PAYLOAD_RESIDENCE_POSTAL_CODE(payload(0x9)),
    PAYLOAD_RESIDENCE_COUNTRY(payload(0xA)),
    PAYLOAD_NATIONALITY(payload(0xD)),
    PAYLOAD_BIRTH_NAME(payload(0xE)),
    PAYLOAD_BIRTH_LOCALITY(payload(0xF)),
    PAYLOAD_ALSO_KNOWN_AS(payload(0x13));
}
