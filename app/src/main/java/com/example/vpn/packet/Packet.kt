package com.example.vpn.packet

import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Encapsulates a parsed IPv4/UDP packet containing a DNS query/response.
 * Designed to provide the foundation for on-device DNS inspection and filtering.
 */
data class DnsPacket(
    val ipHeader: IpHeader,
    val udpHeader: UdpHeader,
    val dnsHeader: DnsHeader,
    val questions: List<DnsQuestion>,
    val rawPayload: ByteArray
) {
    /**
     * Convenient accessor for the primary domain being queried.
     */
    val primaryDomain: String?
        get() = questions.firstOrNull()?.qName

    /**
     * Convenient accessor for the query type of the primary question.
     */
    val primaryQueryType: DnsQueryType
        get() = questions.firstOrNull()?.queryType ?: DnsQueryType.UNKNOWN

    val isQuery: Boolean
        get() = !dnsHeader.isResponse && dnsHeader.opcode == 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DnsPacket
        return ipHeader == other.ipHeader &&
                udpHeader == other.udpHeader &&
                dnsHeader == other.dnsHeader &&
                questions == other.questions
    }

    override fun hashCode(): Int {
        var result = ipHeader.hashCode()
        result = 31 * result + udpHeader.hashCode()
        result = 31 * result + dnsHeader.hashCode()
        result = 31 * result + questions.hashCode()
        return result
    }
}

/**
 * Representation of IPv4 Header (RFC 791).
 */
data class IpHeader(
    val version: Int,
    val ihl: Int, // Internet Header Length in bytes
    val dscp: Int,
    val totalLength: Int,
    val identification: Int,
    val ttl: Int,
    val protocol: Int, // 17 for UDP
    val sourceIp: InetAddress,
    val destinationIp: InetAddress
)

/**
 * Representation of UDP Header (RFC 768).
 */
data class UdpHeader(
    val sourcePort: Int,
    val destinationPort: Int,
    val length: Int,
    val checksum: Int
)

/**
 * Representation of DNS Header (RFC 1035).
 *
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
data class DnsHeader(
    val id: Int,
    val flags: Int,
    val isResponse: Boolean,      // QR: 0 = Query, 1 = Response
    val opcode: Int,              // 0 = Standard Query (QUERY)
    val isAuthoritative: Boolean, // AA
    val isTruncated: Boolean,     // TC
    val recursionDesired: Boolean,// RD
    val recursionAvailable: Boolean, // RA
    val responseCode: Int,        // RCODE: 0 = NOERROR, 3 = NXDOMAIN
    val qdCount: Int,             // Number of questions
    val anCount: Int,             // Number of answers
    val nsCount: Int,             // Number of authority records
    val arCount: Int              // Number of additional records
)

/**
 * Representation of DNS Question section (RFC 1035).
 */
data class DnsQuestion(
    val qName: String,
    val qType: Int,
    val qClass: Int
) {
    val queryType: DnsQueryType
        get() = DnsQueryType.fromCode(qType)
}

/**
 * Well-known DNS Query Types.
 */
enum class DnsQueryType(val code: Int) {
    A(1),
    NS(2),
    CNAME(5),
    SOA(6),
    PTR(12),
    MX(15),
    TXT(16),
    AAAA(28),
    SRV(33),
    HTTPS(65),
    ANY(255),
    UNKNOWN(-1);

    companion object {
        fun fromCode(code: Int): DnsQueryType =
            entries.firstOrNull { it.code == code } ?: UNKNOWN
    }
}
