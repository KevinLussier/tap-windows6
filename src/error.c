/*
 *  TAP-Windows -- A kernel driver to provide virtual tap
 *                 device functionality on Windows.
 *
 *  This code was inspired by the CIPE-Win32 driver by Damion K. Wilson.
 *
 *  This source code is Copyright (C) 2002-2014 OpenVPN Technologies, Inc.,
 *  and is released under the GPL version 2 (see below).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tap.h"

//-----------------
// DEBUGGING OUTPUT
//-----------------

const char *g_LastErrorFilename;
int g_LastErrorLineNumber;

#if DBG

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

DebugOutput g_Debug;

BOOLEAN
NewlineExists (const char *str, int len)
{
    while (len-- > 0)
    {
        const char c = *str++;
        if (c == '\n')
            return TRUE;
        else if (c == '\0')
            break;
    }
    return FALSE;
}

VOID
MyDebugInit (unsigned int bufsiz)
{
    NdisZeroMemory (&g_Debug, sizeof (g_Debug));
    g_Debug.text = (char *) MemAlloc (bufsiz, FALSE);

    if (g_Debug.text)
    {
        g_Debug.capacity = bufsiz;
    }
}

VOID
MyDebugFree ()
{
    if (g_Debug.text)
    {
        MemFree (g_Debug.text, g_Debug.capacity);
    }

    NdisZeroMemory (&g_Debug, sizeof (g_Debug));
}

VOID
MyDebugPrint (ULONG level, const unsigned char* format, ...)
{
    va_list args;

#if ALSO_DBGPRINT
    va_start (args, format);
    vDbgPrintEx (DPFLTR_IHVNETWORK_ID, level, format, args);
    va_end (args);
#endif

    if (g_Debug.text && g_Debug.capacity > 0 && CAN_WE_PRINT)
    {
        BOOLEAN owned;
        ACQUIRE_MUTEX_ADAPTIVE (&g_Debug.lock, owned);
        if (owned)
        {
            const int remaining = (int)g_Debug.capacity - (int)g_Debug.out;

            if (remaining > 0)
            {
                NTSTATUS status;
                char *end;

                va_start (args, format);
                status = RtlStringCchVPrintfExA (g_Debug.text + g_Debug.out,
                    remaining,
                    &end,
                    NULL,
                    STRSAFE_NO_TRUNCATION | STRSAFE_IGNORE_NULLS,
                    format,
                    args);
                va_end (args);
                if (status == STATUS_SUCCESS)
                    g_Debug.out = (unsigned int) (end - g_Debug.text);
                else
                    g_Debug.error = TRUE;
            }
            else
                g_Debug.error = TRUE;

            RELEASE_MUTEX (&g_Debug.lock);
        }
        else
            g_Debug.error = TRUE;
    }
}

BOOLEAN
GetDebugLine (
    __in char *buf,
    __in const int len
    )
{
    static const char *truncated = "[OUTPUT TRUNCATED]\n";
    BOOLEAN ret = FALSE;

    NdisZeroMemory (buf, len);

    if (g_Debug.text && g_Debug.capacity > 0)
    {
        BOOLEAN owned;
        ACQUIRE_MUTEX_ADAPTIVE (&g_Debug.lock, owned);
        if (owned)
        {
            int i = 0;

            if (g_Debug.error || NewlineExists (g_Debug.text + g_Debug.in, (int)g_Debug.out - (int)g_Debug.in))
            {
                while (i < (len - 1) && g_Debug.in < g_Debug.out)
                {
                    const char c = g_Debug.text[g_Debug.in++];
                    if (c == '\n')
                        break;
                    buf[i++] = c;
                }
                if (i < len)
                    buf[i] = '\0';
            }

            if (!i)
            {
                if (g_Debug.in == g_Debug.out)
                {
                    g_Debug.in = g_Debug.out = 0;
                    if (g_Debug.error)
                    {
                        const unsigned int tlen = strlen (truncated);
                        if (tlen < g_Debug.capacity)
                        {
                            NdisMoveMemory (g_Debug.text, truncated, tlen+1);
                            g_Debug.out = tlen;
                        }
                        g_Debug.error = FALSE;
                    }
                }
            }
            else
                ret = TRUE;

            RELEASE_MUTEX (&g_Debug.lock);
        }      
    }
    return ret;
}

VOID
PrMac (const MACADDR mac)
{
  DEBUGT ("%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);
}

VOID
PrIP (IPADDR ip_addr)
{
  const unsigned char *ip = (const unsigned char *) &ip_addr;

  DEBUGT ("%d.%d.%d.%d",
        ip[0], ip[1], ip[2], ip[3]);
}

VOID
PrIPV6 (IPV6ADDR ip_addr)
{
    DEBUGT("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
        ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3],
        ip_addr[4], ip_addr[5], ip_addr[6], ip_addr[7],
        ip_addr[8], ip_addr[9], ip_addr[10], ip_addr[11],
        ip_addr[12], ip_addr[13], ip_addr[14], ip_addr[15]);
}

const char *
PrIPProto (int proto)
{
    switch (proto)
    {
    case IPPROTO_HOPOPT:
        return "HOPOPT";

    case IPPROTO_UDP:
        return "UDP";

    case IPPROTO_TCP:
        return "TCP";

    case IPPROTO_ICMP:
        return "ICMP";

    case IPPROTO_IGMP:
        return "IGMP";

    case IPPROTO_ESP:
        return "ESP";

    case IPPROTO_AH:
        return "AH";

    case IPPROTO_ICMPV6:
        return "ICMPV6";

    default:
        return "???";
    }
}

VOID
DumpARP (const char *prefix, const ARP_PACKET *arp)
{
  DEBUGT ("%s ARP src=", prefix);
  PrMac (arp->m_MAC_Source);
  DEBUGT (" dest=");
  PrMac (arp->m_MAC_Destination);
  DEBUGT (" OP=0x%04x",
        (int)ntohs(arp->m_ARP_Operation));
  DEBUGT (" M=0x%04x(%d)",
        (int)ntohs(arp->m_MAC_AddressType),
        (int)arp->m_MAC_AddressSize);
  DEBUGT (" P=0x%04x(%d)",
        (int)ntohs(arp->m_PROTO_AddressType),
        (int)arp->m_PROTO_AddressSize);

  DEBUGT (" MacSrc=");
  PrMac (arp->m_ARP_MAC_Source);
  DEBUGT (" MacDest=");
  PrMac (arp->m_ARP_MAC_Destination);

  DEBUGT (" IPSrc=");
  PrIP (arp->m_ARP_IP_Source);
  DEBUGT (" IPDest=");
  PrIP (arp->m_ARP_IP_Destination);

  DEBUGT ("\n");
}

struct ethpayload
{
  ETH_HEADER eth;
  UCHAR payload[DEFAULT_PACKET_LOOKAHEAD];
};

#ifdef ALLOW_PACKET_DUMP

VOID
DumpPacket2(
    __in const char *prefix,
    __in const ETH_HEADER *eth,
    __in const unsigned char *data,
    __in unsigned int len
    )
{
    struct ethpayload *ep = (struct ethpayload *) MemAlloc (sizeof (struct ethpayload), TRUE);
    if (ep)
    {
        if (len > DEFAULT_PACKET_LOOKAHEAD)
            len = DEFAULT_PACKET_LOOKAHEAD;
        ep->eth = *eth;
        NdisMoveMemory (ep->payload, data, len);
        DumpPacket (prefix, (unsigned char *) ep, sizeof (ETH_HEADER) + len);
        MemFree (ep, sizeof (struct ethpayload));
    }
}

VOID
DumpPacket(
    __in const char *prefix,
    __in const unsigned char *data,
    __in unsigned int len
    )
{
    const ETH_HEADER *eth = (const ETH_HEADER *) data;
    const IPHDR *ip = (const IPHDR *)(data + sizeof(ETH_HEADER));
    const IPV6HDR *ip6 = (const IPV6HDR *) (data + sizeof (ETH_HEADER));

    if (len < sizeof (ETH_HEADER))
    {
        DEBUGE ("%s TRUNCATED PACKET LEN=%d\n", prefix, len);
        return;
    }

    // ARP Packet?
    if (len >= sizeof (ARP_PACKET) && eth->proto == htons (ETH_P_ARP))
    {
        DumpARP (prefix, (const ARP_PACKET *) data);
        return;
    }

    // IPv4 packet?
    if (len >= (sizeof (IPHDR) + sizeof (ETH_HEADER))
        && eth->proto == htons (ETH_P_IP)
        && IPH_GET_VER (ip->version_len) == 4)
    {
        const int hlen = IPH_GET_LEN (ip->version_len);
        const int blen = len - sizeof (ETH_HEADER);
        BOOLEAN did = FALSE;

        DEBUGT ("%s IPv4 %s[%d]", prefix, PrIPProto (ip->protocol), len);

        if (!(ntohs (ip->tot_len) == blen && hlen <= blen))
        {
            DEBUGT (" XXX\n");
            return;
        }

        // TCP packet?
        if (ip->protocol == IPPROTO_TCP
            && blen - hlen >= (sizeof (TCPHDR)))
        {
            const TCPHDR *tcp = (TCPHDR *) (data + sizeof (ETH_HEADER) + hlen);
            DEBUGT (" ");
            PrIP (ip->saddr);
            DEBUGT (":%d", ntohs (tcp->source));
            DEBUGT (" -> ");
            PrIP (ip->daddr);
            DEBUGT (":%d", ntohs (tcp->dest));
            did = TRUE;
        }

        // UDP packet?
        else if ((ntohs (ip->frag_off) & IP_OFFMASK) == 0
            && ip->protocol == IPPROTO_UDP
            && blen - hlen >= (sizeof (UDPHDR)))
        {
            const UDPHDR *udp = (UDPHDR *) (data + sizeof (ETH_HEADER) + hlen);

            // DHCP packet?
            if ((udp->dest == htons (BOOTPC_PORT) || udp->dest == htons (BOOTPS_PORT))
                && blen - hlen >= (sizeof (UDPHDR) + sizeof (DHCP)))
            {
                const DHCP *dhcp = (DHCP *) (data
                    + hlen
                    + sizeof (ETH_HEADER)
                    + sizeof (UDPHDR));

                int optlen = len
                    - sizeof (ETH_HEADER)
                    - hlen
                    - sizeof (UDPHDR)
                    - sizeof (DHCP);

                if (optlen < 0)
                    optlen = 0;

                DumpDHCP (eth, ip, udp, dhcp, optlen);
                did = TRUE;
            }

            if (!did)
            {
                DEBUGT (" ");
                PrIP (ip->saddr);
                DEBUGT (":%d", ntohs (udp->source));
                DEBUGT (" -> ");
                PrIP (ip->daddr);
                DEBUGT (":%d", ntohs (udp->dest));
                did = TRUE;
            }
        }

        if (!did)
        {
            DEBUGT (" ipproto=%d ", ip->protocol);
            PrIP (ip->saddr);
            DEBUGT (" -> ");
            PrIP (ip->daddr);
        }

        DEBUGT ("\n");
        return;
    }

    // IPv6 packet?
    if (len >= (sizeof(IPV6HDR) + sizeof(ETH_HEADER))
        && eth->proto == htons(ETH_P_IPV6)
        && IPV6H_GET_VER(ip6->version_prio) == 6)
    {
        const int hlen = sizeof(IPV6HDR); // EXTENSIONS NOT SUPPORTED
        const int blen = len - sizeof(ETH_HEADER);
        const UDPTCPHDR *udptcp = (UDPTCPHDR *)(data + sizeof(ETH_HEADER) + hlen);

        DEBUGT ("%s IPv6 %s[%d]", prefix, PrIPProto(ip6->nexthdr), len);

        if (!((ntohs(ip6->payload_len) + hlen) == blen && hlen <= blen))
        {
            DEBUGT(" XXX\n");
            return;
        }

        DEBUGT (" ");
        PrIPV6 (ip6->saddr);
        DEBUGT (":%d", ntohs (udptcp->source));
        DEBUGT (" -> ");
        PrIPV6 (ip6->daddr);
        DEBUGT (":%d", ntohs (udptcp->dest));

        DEBUGT("\n");
        return;
    }

    {
        DEBUGT ("%s ??? src=", prefix);
        PrMac (eth->src);
        DEBUGT (" dest=");
        PrMac (eth->dest);
        DEBUGT (" proto=0x%04x len=%d\n",
            (int) ntohs(eth->proto),
            len);
    }
}

#endif // ALLOW_PACKET_DUMP

#endif
