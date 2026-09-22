package com.example

import com.example.vpn.packet.DnsPacketParser
import com.example.vpn.packet.DnsQueryType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

class DnsPacketParserTest {

    @Test
    fun parse_validDnsQueryPacket_extractsHeaderAndQuestionAccurately() {
        // Build an authentic IPv4 / UDP / DNS datagram querying "example.com" (Type A)
        val packetBytes = byteArrayOf(
            // IPv4 Header (20 bytes)
            0x45.toByte(), 0x00.toByte(), 0x00.toByte(), 0x39.toByte(), // Total len = 57
            0xAB.toByte(), 0xCD.toByte(), 0x40.toByte(), 0x00.toByte(), // ID, Flags DF
            0x40.toByte(), 0x11.toByte(), 0x00.toByte(), 0x00.toByte(), // TTL 64, Protocol 17 (UDP)
            192.toByte(), 168.toByte(), 1.toByte(), 100.toByte(),       // Src: 192.168.1.100
            10.toByte(), 10.toByte(), 10.toByte(), 2.toByte(),          // Dst: 10.10.10.2

            // UDP Header (8 bytes)
            0xD4.toByte(), 0x31.toByte(),                               // Src port: 54321
            0x00.toByte(), 0x35.toByte(),                               // Dst port: 53 (DNS)
            0x00.toByte(), 0x25.toByte(),                               // UDP Length: 37 bytes (8 UDP + 29 DNS)
            0x00.toByte(), 0x00.toByte(),                               // Checksum

            // DNS Header (12 bytes)
            0x12.toByte(), 0x34.toByte(),                               // ID: 0x1234
            0x01.toByte(), 0x00.toByte(),                               // Flags: Standard query, RD=1
            0x00.toByte(), 0x01.toByte(),                               // QDCOUNT: 1
            0x00.toByte(), 0x00.toByte(),                               // ANCOUNT: 0
            0x00.toByte(), 0x00.toByte(),                               // NSCOUNT: 0
            0x00.toByte(), 0x00.toByte(),                               // ARCOUNT: 0

            // DNS Question (example.com, Type A, Class IN)
            0x07.toByte(), 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03.toByte(), 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00.toByte(),                                              // End of QNAME
            0x00.toByte(), 0x01.toByte(),                               // QTYPE: 1 (A)
            0x00.toByte(), 0x01.toByte()                                // QCLASS: 1 (IN)
        )

        val buffer = ByteBuffer.wrap(packetBytes)
        val dnsPacket = DnsPacketParser.parse(buffer, packetBytes.size)

        assertNotNull("Le paquet DNS aurait dû être parsé avec succès", dnsPacket)
        assertEquals("192.168.1.100", dnsPacket!!.ipHeader.sourceIp.hostAddress)
        assertEquals("10.10.10.2", dnsPacket.ipHeader.destinationIp.hostAddress)
        assertEquals(54321, dnsPacket.udpHeader.sourcePort)
        assertEquals(53, dnsPacket.udpHeader.destinationPort)

        assertEquals(0x1234, dnsPacket.dnsHeader.id)
        assertTrue("Devrait être identifié comme une requête", dnsPacket.isQuery)
        assertEquals(1, dnsPacket.questions.size)

        val question = dnsPacket.questions[0]
        assertEquals("example.com", question.qName)
        assertEquals(DnsQueryType.A, question.queryType)
        assertEquals(1, question.qClass)
    }

    @Test
    fun parse_nonDnsUdpTraffic_returnsNull() {
        val nonDnsPacket = byteArrayOf(
            0x45.toByte(), 0x00.toByte(), 0x00.toByte(), 0x20.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x40.toByte(), 0x11.toByte(), 0x00.toByte(), 0x00.toByte(),
            10.toByte(), 0.toByte(), 0.toByte(), 1.toByte(),
            10.toByte(), 0.toByte(), 0.toByte(), 2.toByte(),
            0x1F.toByte(), 0x90.toByte(), 0x1F.toByte(), 0x91.toByte(), // Ports 8080 -> 8081 (pas port 53)
            0x00.toByte(), 0x0C.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x01.toByte(), 0x02.toByte(), 0x03.toByte(), 0x04.toByte()
        )

        val buffer = ByteBuffer.wrap(nonDnsPacket)
        val result = DnsPacketParser.parse(buffer, nonDnsPacket.size)
        assertNull("Le trafic non-port 53 ne doit pas être traité par le parser DNS", result)
    }

    @Test
    fun parse_truncatedMalformedPacket_returnsNullWithoutCrashing() {
        val truncated = byteArrayOf(0x45.toByte(), 0x00.toByte(), 0x00.toByte(), 0x14.toByte())
        val buffer = ByteBuffer.wrap(truncated)
        val result = DnsPacketParser.parse(buffer, truncated.size)
        assertNull("Un paquet tronqué doit retourner null sans exception", result)
    }
}
