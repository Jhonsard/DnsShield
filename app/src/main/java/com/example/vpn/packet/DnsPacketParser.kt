package com.example.vpn.packet

import android.util.Log
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * High-performance parser for IPv4/UDP packets encapsulating DNS queries.
 *
 * Implements strict boundary checking and RFC 1035 label extraction to ensure
 * resilience against malformed or malicious network payloads.
 */
object DnsPacketParser {

    private const val TAG = "DnsPacketParser"
    private const val PROTOCOL_UDP = 17
    private const val DNS_PORT = 53
    private const val DNS_HEADER_LENGTH = 12

    /**
     * Attempts to parse an IPv4/UDP datagram and extract the encapsulated DNS query.
     *
     * @param buffer Direct or heap ByteBuffer positioned at index 0.
     * @param length Total length of the IP packet.
     * @return [DnsPacket] if valid UDP DNS packet on port 53, or null otherwise.
     */
    fun parse(buffer: ByteBuffer, length: Int): DnsPacket? {
        if (length < 28) return null // Minimum IPv4 (20) + UDP (8)

        // -------------------------------------------------------------
        // 1. Parse IPv4 Header
        // -------------------------------------------------------------
        val firstByte = buffer.get(0).toInt() and 0xFF
        val version = firstByte shr 4
        if (version != 4) {
            // Non-IPv4 packets are skipped in this parser
            return null
        }

        val ihl = (firstByte and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8) return null

        val totalLength = buffer.getShort(2).toInt() and 0xFFFF
        val id = buffer.getShort(4).toInt() and 0xFFFF
        val ttl = buffer.get(8).toInt() and 0xFF
        val protocol = buffer.get(9).toInt() and 0xFF

        if (protocol != PROTOCOL_UDP) return null

        val srcIpBytes = ByteArray(4)
        val dstIpBytes = ByteArray(4)
        for (i in 0 until 4) srcIpBytes[i] = buffer.get(12 + i)
        for (i in 0 until 4) dstIpBytes[i] = buffer.get(16 + i)

        val sourceIp = InetAddress.getByAddress(srcIpBytes)
        val destinationIp = InetAddress.getByAddress(dstIpBytes)

        val ipHeader = IpHeader(
            version = version,
            ihl = ihl,
            dscp = (buffer.get(1).toInt() and 0xFF) shr 2,
            totalLength = totalLength,
            identification = id,
            ttl = ttl,
            protocol = protocol,
            sourceIp = sourceIp,
            destinationIp = destinationIp
        )

        // -------------------------------------------------------------
        // 2. Parse UDP Header
        // -------------------------------------------------------------
        val udpOffset = ihl
        val srcPort = buffer.getShort(udpOffset).toInt() and 0xFFFF
        val dstPort = buffer.getShort(udpOffset + 2).toInt() and 0xFFFF
        val udpLength = buffer.getShort(udpOffset + 4).toInt() and 0xFFFF
        val udpChecksum = buffer.getShort(udpOffset + 6).toInt() and 0xFFFF

        // Only process DNS traffic directed to or from port 53
        if (dstPort != DNS_PORT && srcPort != DNS_PORT) return null
        if (udpLength < 8 || length < udpOffset + udpLength) return null

        val udpHeader = UdpHeader(
            sourcePort = srcPort,
            destinationPort = dstPort,
            length = udpLength,
            checksum = udpChecksum
        )

        // -------------------------------------------------------------
        // 3. Parse DNS Header (RFC 1035 §4.1.1)
        // -------------------------------------------------------------
        val dnsOffset = udpOffset + 8
        val dnsPayloadLength = udpLength - 8
        if (dnsPayloadLength < DNS_HEADER_LENGTH) return null

        val dnsId = buffer.getShort(dnsOffset).toInt() and 0xFFFF
        val rawFlags = buffer.getShort(dnsOffset + 2).toInt() and 0xFFFF
        val qdCount = buffer.getShort(dnsOffset + 4).toInt() and 0xFFFF
        val anCount = buffer.getShort(dnsOffset + 6).toInt() and 0xFFFF
        val nsCount = buffer.getShort(dnsOffset + 8).toInt() and 0xFFFF
        val arCount = buffer.getShort(dnsOffset + 10).toInt() and 0xFFFF

        val dnsHeader = DnsHeader(
            id = dnsId,
            flags = rawFlags,
            isResponse = ((rawFlags shr 15) and 0x01) == 1,
            opcode = (rawFlags shr 11) and 0x0F,
            isAuthoritative = ((rawFlags shr 10) and 0x01) == 1,
            isTruncated = ((rawFlags shr 9) and 0x01) == 1,
            recursionDesired = ((rawFlags shr 8) and 0x01) == 1,
            recursionAvailable = ((rawFlags shr 7) and 0x01) == 1,
            responseCode = rawFlags and 0x0F,
            qdCount = qdCount,
            anCount = anCount,
            nsCount = nsCount,
            arCount = arCount
        )

        // -------------------------------------------------------------
        // 4. Parse Question Section(s) (RFC 1035 §4.1.2)
        // -------------------------------------------------------------
        val questions = mutableListOf<DnsQuestion>()
        var currentOffset = dnsOffset + DNS_HEADER_LENGTH
        val maxOffset = dnsOffset + dnsPayloadLength

        try {
            for (q in 0 until qdCount) {
                if (currentOffset >= maxOffset) break

                val (domain, nextOffset) = readDomainName(buffer, currentOffset, dnsOffset, maxOffset)
                currentOffset = nextOffset

                if (currentOffset + 4 > maxOffset) break

                val qType = buffer.getShort(currentOffset).toInt() and 0xFFFF
                val qClass = buffer.getShort(currentOffset + 2).toInt() and 0xFFFF
                currentOffset += 4

                questions.add(
                    DnsQuestion(
                        qName = domain,
                        qType = qType,
                        qClass = qClass
                    )
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "Erreur lors du parsing des questions DNS", e)
            return null
        }

        // Copy raw DNS payload for downstream forwarding or forging
        val rawDnsPayload = ByteArray(dnsPayloadLength)
        val prevPos = buffer.position()
        buffer.position(dnsOffset)
        buffer.get(rawDnsPayload, 0, dnsPayloadLength)
        buffer.position(prevPos)

        return DnsPacket(
            ipHeader = ipHeader,
            udpHeader = udpHeader,
            dnsHeader = dnsHeader,
            questions = questions,
            rawPayload = rawDnsPayload
        )
    }

    /**
     * Reads a domain name in DNS wire format (series of length-prefixed labels).
     * Handles RFC 1035 compression pointers (0xC0 prefix) safely with recursion limits.
     */
    private fun readDomainName(
        buffer: ByteBuffer,
        startOffset: Int,
        dnsBaseOffset: Int,
        maxOffset: Int
    ): Pair<String, Int> {
        val labels = mutableListOf<String>()
        var offset = startOffset
        var jumped = false
        var postJumpOffset = -1
        var jumpsCount = 0
        val maxJumps = 5 // Prevent compression pointer loop bombs

        while (offset < maxOffset) {
            val length = buffer.get(offset).toInt() and 0xFF

            if (length == 0) {
                // End of label sequence (root dot)
                offset++
                break
            }

            // Check for pointer (two highest bits set: 0b11xxxxxx = 0xC0)
            if ((length and 0xC0) == 0xC0) {
                if (offset + 1 >= maxOffset) break
                val secondByte = buffer.get(offset + 1).toInt() and 0xFF
                val pointerOffset = dnsBaseOffset + (((length and 0x3F) shl 8) or secondByte)

                if (!jumped) {
                    postJumpOffset = offset + 2
                    jumped = true
                }

                jumpsCount++
                if (jumpsCount > maxJumps || pointerOffset >= maxOffset) {
                    break // Avoid infinite loops or OOB
                }
                offset = pointerOffset
                continue
            }

            // Standard label
            offset++
            if (offset + length > maxOffset) break

            val labelBytes = ByteArray(length)
            for (i in 0 until length) {
                labelBytes[i] = buffer.get(offset + i)
            }
            labels.add(String(labelBytes, Charsets.US_ASCII))
            offset += length
        }

        val domain = if (labels.isEmpty()) "." else labels.joinToString(".")
        val returnOffset = if (jumped && postJumpOffset != -1) postJumpOffset else offset
        return Pair(domain, returnOffset)
    }
}
