/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(
        struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  
  sr_ethernet_hdr_t * ether_hdr = (sr_ethernet_hdr_t *) packet;

  uint16_t ether_type = ntohs(ether_hdr->ether_type);
  printf("*** -> ether_type %04X \n",ether_type);
  if (ethertype_arp == ether_type)
  {
    printf("*** -> Is Arp \n");
    sr_handle_arp_packet(sr, ether_hdr, packet + sizeof(sr_ethernet_hdr_t), len, interface);
  }
  else if (ethertype_ip == ntohs(ether_hdr->ether_type))
  {
    printf("*** -> Is Ip: use nat: %d \n", sr->use_nat);
    if (sr->use_nat)
      sr_handle_ip_packet_with_nat(sr, ether_hdr, packet + sizeof(sr_ethernet_hdr_t), len, interface);
    else
      sr_handle_ip_packet(sr, ether_hdr, packet + sizeof(sr_ethernet_hdr_t), len, interface);
  }
  else{
    printf("Neither ip packet, nor arp packet?\n");
    fprintf(stderr, "Neither ip packet, nor arp packet?\n");
  }
}/* end sr_ForwardPacket */

void sr_handle_ip_packet(
        struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * ether_payload/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ether_payload;

  /* Check crc. */
  /* https://tools.ietf.org/html/rfc1071 */
  uint16_t orig_sum = ip_hdr->ip_sum;
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  ip_hdr->ip_sum = 0;
  uint16_t new_sum = cksum(ether_payload, ip_hdr_len); /* Already in network byte order. */
  
  if (new_sum != orig_sum)
  {
    fprintf(stderr, "IP header checksum missmatch! orig: %d, new: %d\n", orig_sum, new_sum);
    return;
  }  

  uint8_t *to_send = NULL; unsigned int to_send_len = -1;

  /* Check dest IP. */
  /**** if packet is sent to me. ****/
  uint32_t ip = ip_hdr->ip_dst;
  if (sr_contains_ip(sr, ip)) 
  {
    fprintf(stderr, "IP addr sent to me (router): %d\n", ip);
    /* Get IP payload protocol. */
    uint8_t protocol = ip_hdr->ip_p;
    if (protocol == ip_protocol_icmp) 
    {
      /* The second field (4 bits) is the Internet Header Length (IHL), which is the number of 32-bit words in the header. */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ether_payload + ip_hdr_len);
      
      if (8 == icmp_hdr->icmp_type) {
        /* Send ICMP echo reply, type = 0, code = 0*/
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, ECHO_REPLY, &to_send, &to_send_len);
        sr_send_icmp(sr, to_send, to_send_len);
        return;
      } 

      fprintf(stderr, "[FATAL] Unhandled icmp type: %d\n", icmp_hdr->icmp_type);
      return;

    }
    else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) 
    {
      /* Send ICMP port unreachable, type = 3, code = 3*/
      sr_create_icmp_packet(sr, ether_hdr, ip_hdr, PORT_UNREACHABLE, &to_send, &to_send_len);
      sr_send_icmp(sr, to_send, to_send_len);
      return;
    } 
    else 
    {
      fprintf(stderr, "[FATAL] Unhandled ip protocl type: %d\n", protocol);
      return;
    }
  }
 
  /**** if packet is not sent to me. ****/
  /* Check the TTL */
  uint8_t ttl = ip_hdr->ip_ttl;
  if (1 >= ttl) 
  {
    fprintf(stderr, "TTL expired.\n");
    /* Send ICMP time exceeded, type = 11, code = 1*/
    sr_create_icmp_packet(sr, ether_hdr, ip_hdr, TIME_EXCEEDED, &to_send, &to_send_len);
    sr_send_icmp(sr, to_send, to_send_len);
    return;
  } 

  /* Prepare to send the packet to the next hop. */
  /* perform the longest prefix match */
  uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
  if (0 != longest_prefix_match(sr, ip_hdr->ip_dst, &next_hop_addr, &if_name)) 
  {
    fprintf(stderr, "[handle ip] Dest IP not found: %d\n", ip);
    /* Send ICMP network unrechable, type = 3, code = 0 */
    sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
    sr_send_icmp(sr, to_send, to_send_len);
    return;
  }

  sr_create_ip_packet(sr, len, ip_hdr, &to_send, &to_send_len);      
  sr_arp_lookup_and_send(sr, to_send, to_send_len, next_hop_addr, if_name);
}

void sr_send_icmp(struct sr_instance *sr, uint8_t *to_send, unsigned int to_send_len)
{
  
  uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
  sr_ip_hdr_t *to_send_ip_hdr = (sr_ip_hdr_t *)(to_send + ETHER_HDR_LEN);
  if (0 != longest_prefix_match(sr, to_send_ip_hdr->ip_dst, &next_hop_addr, &if_name))
  {
      fprintf(stderr, "[send icmp] Dest IP not found, cannot send ICMP message!\n");
      return;
  }

  sr_arp_lookup_and_send(sr, to_send, to_send_len, next_hop_addr, if_name);
}

/* A return value of true means forwarding is needed. */
bool sr_handle_ip_packet_with_nat(
        struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * ether_payload/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{                                  
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ether_payload;
  /* check checksum */
  uint16_t orig_sum = ip_hdr->ip_sum;
  uint32_t ip_hdr_len =ip_hdr->ip_hl * sizeof(uint32_t);
  
  ip_hdr->ip_sum = 0;
  uint16_t new_sum = cksum(ether_payload, ip_hdr_len); /* Already in network byte order. */
  
  if (new_sum != orig_sum)
  {
    fprintf(stderr, "IP header checksum missmatch! orig: %d, new: %d\n", orig_sum, new_sum);
    return false;
  }
  uint8_t protocol = ip_hdr->ip_p;

  if (protocol == ip_protocol_icmp) 
  {
    printf("====> is icmp for nat\n");
    bool ret = sr_handle_icmp_packet_with_nat(sr, ether_hdr, ether_payload, len, interface);  
    assert(ret != false);
    return ret;
  }
  else if (protocol == ip_protocol_tcp) 
  {
    printf("====> is tcp for nat\n");
    return sr_handle_tcp_packet_with_nat(sr, ether_hdr, ether_payload, len, interface); 
  }
  else
  {
    return false;
  }
}                                  

static bool is_request_query_icmp_packet(sr_icmp_hdr_t *icmp_hdr)
{
  if (8 == icmp_hdr->icmp_type) return true;  /* Echo request */
  if (13 == icmp_hdr->icmp_type) return true; /* Timestamp request */
  if (15 == icmp_hdr->icmp_type) return true; /* Information request */
  return false;
}

static bool is_reply_query_icmp_packet(sr_icmp_hdr_t *icmp_hdr)
{
  if (0 == icmp_hdr->icmp_type) return true;  /* Echo reply */
  if (14 == icmp_hdr->icmp_type) return true; /* Timestamp reply */
  if (16 == icmp_hdr->icmp_type) return true; /* Information reply */
  return false;
}

static bool is_error_icmp_packet(sr_icmp_hdr_t *icmp_hdr)
{
  if (3 == icmp_hdr->icmp_type) return true; /* Destination Unreachable */
  if (4 == icmp_hdr->icmp_type) return true; /* Source Quench */
  if (5 == icmp_hdr->icmp_type) return true; /* Redirect: FIXME is this an error? */
  if (11 == icmp_hdr->icmp_type) return true; /* Time Exceeded */
  if (12 == icmp_hdr->icmp_type) return true; /* Parameter Problem */
  return false;
}

static bool get_port_from_error_icmp_packet(
              sr_icmp_hdr_t *icmp_hdr, uint16_t *port, char *interface)
{
  sr_ip_hdr_t *embedded_ip_hdr = (sr_ip_hdr_t *)(((uint8_t *)icmp_hdr) + ICMP_HDR_FULL_LEN);
 /* uint32_t ip_ext = embedded_ip_hdr->ip_src; */
  uint8_t embedded_protocol = embedded_ip_hdr->ip_p;
  uint32_t embedded_ip_hdr_len = embedded_ip_hdr->ip_hl * sizeof(uint32_t);
  uint8_t * embedded_ip_payload = ((uint8_t *)embedded_ip_hdr) + embedded_ip_hdr_len;
  /* embedded ip payload is icmp. */
  if (embedded_protocol == ip_protocol_icmp)
  {
    sr_icmp_full_hdr_t *double_embedded_icmp_hdr = (sr_icmp_full_hdr_t *) embedded_ip_payload;
    (*port) = double_embedded_icmp_hdr->icmp_seq_num;
  }
  /* embedded ip payload is tcp. */
  else if (embedded_protocol == ip_protocol_tcp)
  {
    sr_tcp_hdr_t *double_embedded_tcp_hdr = (sr_tcp_hdr_t *) embedded_ip_payload;
    if (is_internal_if(interface)) 
      (*port) = double_embedded_tcp_hdr->tcp_dst_port;
    else if (is_external_if(interface)) 
      (*port) = double_embedded_tcp_hdr->tcp_src_port;
  }
  else 
  {
    fprintf(stderr, "[FATAL] Unhandled icmp error payload protocol: %d\n", embedded_protocol);
    return false;
  }
  
  return true;
}

/* A return value of true means forwarding is needed. */
bool sr_handle_icmp_packet_with_nat(
        struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * ether_payload/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ether_payload;
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ether_payload + ip_hdr_len);
  struct sr_nat_mapping * mapping = NULL;
  uint8_t *to_send = NULL; unsigned int to_send_len = -1;
  uint32_t true_dst_ip = 0;  /*NBO */

  /* TODO: validate the icmp checksum. */

  /****** For me. ******/ 
  if (is_internal_if(interface)) 
  {
    printf("======> is internal interface and for me\n");
    if (sr_contains_ip(sr, ip_hdr->ip_dst)) 
    {
      if (8 == icmp_hdr->icmp_type) 
      {
        printf("\t\tIs request icmp\n");
        /* Send ICMP echo reply, type = 0, code = 0*/
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, ECHO_REPLY, &to_send, &to_send_len);
        sr_send_icmp(sr, to_send, to_send_len);
        return true;
      } 
      else
      {
        fprintf(stderr, "[FATAL] Unhandled icmp type: %d, code: %d\n", 
                    icmp_hdr->icmp_type, icmp_hdr->icmp_code);
        return false;
      }
    } 
  }
  else if (is_external_if(interface))
  {
    printf("======> is external interface and for me\n");
    /* If not mapping exist, is pinging the server.*/ 
    if (is_request_query_icmp_packet(icmp_hdr)) 
    {
      printf("\t\tIs request icmp\n");
      if (ip_hdr->ip_dst != sr->nat->external_ip) 
      {
        printf("\t\tdst is not equal to me!\n");
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
        sr_send_icmp(sr, to_send, to_send_len);
        return false;   
      }

      uint16_t port_ext = ((sr_icmp_full_hdr_t *) icmp_hdr)->icmp_seq_num;  
      mapping = sr_nat_lookup_external(sr->nat, port_ext, nat_mapping_icmp);
    
      if (NULL == mapping) { 
        printf("\t\tmapping found\n");
        /* Send ICMP echo reply, type = 0, code = 0*/
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, ECHO_REPLY, &to_send, &to_send_len);
        sr_send_icmp(sr, to_send, to_send_len);
        return true; 
      }
    } 
  }

  /****** Check the TTL ******/
  uint8_t ttl = ip_hdr->ip_ttl;
  if (1 >= ttl) 
  {
    fprintf(stderr, "icmp packet's TTL expired.\n");
    /* Send ICMP time exceeded, type = 11, code = 1*/
    sr_create_icmp_packet(sr, ether_hdr, ip_hdr, TIME_EXCEEDED, &to_send, &to_send_len);
    sr_send_icmp(sr, to_send, to_send_len);
    return true;
  } 

  /****** Not for me. ******/ 
  if (is_internal_if(interface)) 
  {
    printf("======> is internal interface and not for me\n");
    uint32_t ip_int = ip_hdr->ip_src;
    uint16_t port_int; 

    /* REQUEST QUERY icmp:  not for me: build mapping if not already exist. */ 
    if (is_request_query_icmp_packet(icmp_hdr) || is_reply_query_icmp_packet(icmp_hdr))
    {
     /* if (is_reply_query_icmp_packet(icmp_hdr))
        fprintf(stderr, "[WARN] Do not expect an outgoing reply query.\n");
      */
      port_int = ((sr_icmp_full_hdr_t *) icmp_hdr)->icmp_seq_num;  
    }
    /* ERROR icmp: send & translate if session already exists for embedded payload. */
    else if (is_error_icmp_packet(icmp_hdr))
    {
      bool success = get_port_from_error_icmp_packet(icmp_hdr, &port_int, interface);
      if (!success) return false;
    }
    else 
    {
      fprintf(stderr, "[FATAL] Unhandled icmp type: %d, code: %d\n", 
                  icmp_hdr->icmp_type, icmp_hdr->icmp_code);
      return false;
    }
    
    mapping = sr_nat_lookup_internal(sr->nat, ip_int, port_int, nat_mapping_icmp);
    if (NULL == mapping) 
    {
      mapping = sr_nat_insert_mapping(sr->nat, ip_int, port_int, nat_mapping_icmp);
      printf("\tInserted a new mapping\n");
    }
    if (NULL == mapping)
    {
      fprintf(stderr, "[FATAL] Cannot allocate internal mapping for icmp packet!\n"); 
      return false;
    }
    print_mapping_helper(mapping);
    true_dst_ip = ip_hdr->ip_dst;
  } 
  /*********** Incoming ***********/
  else if (is_external_if(interface))
  {
    /*
    if (ip_hdr->ip_dst != sr->nat->external_ip) 
    {
      printf("\t\tdst is not equal to me!\n");
      sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
      sr_send_icmp(sr, to_send, to_send_len);
      return false;   
    }*/

    printf("======> is external interface and not for me\n");
    uint16_t port_ext;

    /* REPLY QUERY icmp: use sequence number to translate. */ 
    if (is_reply_query_icmp_packet(icmp_hdr) || is_request_query_icmp_packet(icmp_hdr)) 
    {
      port_ext = ((sr_icmp_full_hdr_t *) icmp_hdr)->icmp_seq_num;  
      /* transform ip and sequence number*/
    }
    /* ERROR icmp: use embedded payload's port/sequence number to translate. */
    else if (is_error_icmp_packet(icmp_hdr))
    {
      bool success = get_port_from_error_icmp_packet(icmp_hdr, &port_ext, interface);
      if (!success) return false;
    }
    else 
    {
      fprintf(stderr, "[FATAL] Unhandled icmp type: %d, code: %d\n", 
                  icmp_hdr->icmp_type, icmp_hdr->icmp_code);
      return false;
    }
    printf("\t\tExternal port is: %d\n", ntohs(port_ext));
    if (NULL == mapping) 
    {
      printf("\t\tLooking up mapping\n");
      mapping = sr_nat_lookup_external(sr->nat, port_ext, nat_mapping_icmp);
    }

    if (NULL == mapping)
    {
      /* Drop the packet. */
      fprintf(stderr, "[FATAL] Cannot find external mapping for icmp packet!\n"); 
      return false;
    }
    print_mapping_helper(mapping);
    true_dst_ip = mapping->ip_int;
  }

  /* Prepare to send the packet to the next hop. */
  /* perform the longest prefix match */
  uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
  if (0 != longest_prefix_match(sr, true_dst_ip, &next_hop_addr, &if_name)) 
  {
    fprintf(stderr, "[handle nat ip]Dest IP not found for icmp packet: %d\n", true_dst_ip);
    /* Send ICMP network unrechable, type = 3, code = 0 */
    sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
    sr_send_icmp(sr, to_send, to_send_len);
    return true;
  }

  sr_create_ip_packet(sr, len, ip_hdr, &to_send, &to_send_len); /* Just copy the packet and decrement TTL */
  sr_arp_lookup_and_send_with_nat(sr, to_send, to_send_len, next_hop_addr, if_name, interface, mapping);

  return true;
}                                  

/* A return value of true means forwarding is needed. */
bool sr_handle_tcp_packet_with_nat(
        struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * ether_payload/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{                                  
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ether_payload;
  struct sr_nat_connection * curr_con = NULL;
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ether_payload + ip_hdr_len);

  if (is_internal_if(interface))
  {
    if (sr_contains_ip(sr, ip_hdr->ip_dst))
    {
      /* send icmp port unreachable */
      uint8_t *to_send = NULL; unsigned int to_send_len = -1;
      sr_create_icmp_packet(sr, ether_hdr, ip_hdr, PORT_UNREACHABLE, &to_send, &to_send_len);
      sr_send_icmp(sr, to_send, to_send_len);
      return false;

    }
    else
    {
      /* Outbound lookup */
      struct sr_nat_mapping *outbound_mapping = sr_nat_lookup_internal_for_tcp(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src_port, ip_hdr->ip_dst, &curr_con);
      if ((!outbound_mapping)||(NULL == curr_con)){
        /* create mapping and insert connection*/
        struct sr_nat_connection conn;
        conn.ip_endpoint = ip_hdr->ip_dst;
        conn.tcp_state = CLOSED;
        tcp_state_machine(sr->nat, tcp_hdr, &conn, interface);
        conn.last_updated = time(NULL);
        conn.seq_num_private = tcp_hdr->tcp_seq_num;
        conn.seq_num_public = 0;
        outbound_mapping = sr_nat_insert_conn_and_mapping_if_not_exist(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src_port, nat_mapping_tcp, &conn);
      }
      else
      {
        /*update connection*/
        tcp_state_machine(sr->nat, tcp_hdr, curr_con, interface);
        curr_con->last_updated = time(NULL);
        sr_nat_update_conn_insert_if_not_exist(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src_port, nat_mapping_tcp, curr_con);
        
      }
      /* rewrite IP address, TCP port and forward */
      uint8_t *to_send = NULL; unsigned int to_send_len = -1;
      uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
      if (0 != longest_prefix_match(sr, ip_hdr->ip_dst, &next_hop_addr, &if_name)) 
      {
        fprintf(stderr, "Dest IP not found for icmp packet: %d\n", ip_hdr->ip_dst);
        /* Send ICMP network unrechable, type = 3, code = 0 */
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
        sr_send_icmp(sr, to_send, to_send_len);
        return false;
      }
      sr_create_ip_packet(sr, len, ip_hdr, &to_send, &to_send_len); /* Just copy the packet and decrement TTL */
      sr_arp_lookup_and_send_with_nat(sr, to_send, to_send_len, next_hop_addr, if_name, interface, outbound_mapping);
      return true;
    }
  }
  else if (is_external_if(interface))
  {
    /* Inbound lookup */
    struct sr_nat_mapping* inbound_mapping = sr_nat_lookup_external_for_tcp(sr->nat, tcp_hdr->tcp_dst_port, ip_hdr->ip_src, &curr_con);
    if (NULL == inbound_mapping)
    {
      /* Check if it is a SYN (simultaneous open) */
      if ((tcp_hdr->tcp_syn == 1) && (tcp_hdr->tcp_ack == 0))
      {
        /* put to unsolicited queue */
        if (ntohs(tcp_hdr->tcp_dst_port) < 1024) 
        {
          uint8_t *to_send; unsigned int to_send_len;
          sr_create_icmp_packet(sr, ether_hdr, ip_hdr, PORT_UNREACHABLE, &to_send, &to_send_len);
          sr_send_icmp(sr, to_send, to_send_len);
 
          return false;
        }

        sr_nat_cache_syn(sr->nat, (uint8_t *)ether_hdr, len);
        return false;
      }
      else
      {
        /* drop packet? */
        return false;
      }
    }
    else
    {
      if (!curr_con)
      {
        /* establish connection */
        struct sr_nat_connection conn;
        conn.ip_endpoint = ip_hdr->ip_src;
        conn.tcp_state = CLOSED;
        tcp_state_machine(sr->nat, tcp_hdr, &conn, interface);
        conn.last_updated = time(NULL);
        conn.seq_num_public = tcp_hdr->tcp_seq_num;
        conn.seq_num_private = 0;
        inbound_mapping = sr_nat_insert_conn_and_mapping_if_not_exist(sr->nat, inbound_mapping->ip_int, inbound_mapping->aux_int, nat_mapping_tcp, &conn);

      }
      else
      {
        /*update connection*/
        tcp_state_machine(sr->nat, tcp_hdr, curr_con, interface);
        curr_con->last_updated = time(NULL);
        sr_nat_update_conn_insert_if_not_exist(sr->nat, inbound_mapping->ip_int, inbound_mapping->aux_int, nat_mapping_tcp, curr_con);
        /* rewrite IP address, TCP port and forward */
        
      }
      uint8_t *to_send = NULL; unsigned int to_send_len = -1;
      uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
      if (0 != longest_prefix_match(sr, inbound_mapping->ip_int, &next_hop_addr, &if_name)) 
      {
        fprintf(stderr, "Dest IP not found for icmp packet: %d\n", ip_hdr->ip_dst);
        /* Send ICMP network unrechable, type = 3, code = 0 */
        sr_create_icmp_packet(sr, ether_hdr, ip_hdr, NETWORK_UNREACHABLE, &to_send, &to_send_len);
        sr_send_icmp(sr, to_send, to_send_len);
        return false;
      }
      sr_create_ip_packet(sr, len, ip_hdr, &to_send, &to_send_len); /* Just copy the packet and decrement TTL */
      sr_arp_lookup_and_send_with_nat(sr, to_send, to_send_len, next_hop_addr, if_name, interface, inbound_mapping);
      return true;
    }
  }
  return true;  
}                                  

static void rewrite_icmp_error_packet_port_for_nat(
    sr_ip_hdr_t *embedded_ip_hdr, uint16_t port, char *interface) 
{
  printf("======> rewriting icmp error packet\n");
  uint8_t embedded_protocol = embedded_ip_hdr->ip_p;
  uint32_t embedded_ip_hdr_len = embedded_ip_hdr->ip_hl * sizeof(uint32_t);
  uint8_t * embedded_ip_payload = ((uint8_t *)embedded_ip_hdr) + embedded_ip_hdr_len;
  /* embedded ip payload is icmp. */
  if (embedded_protocol == ip_protocol_icmp)
  {
    sr_icmp_full_hdr_t *double_embedded_icmp_hdr = (sr_icmp_full_hdr_t *) embedded_ip_payload;
    double_embedded_icmp_hdr->icmp_seq_num = port;
  }
  /* embedded ip payload is tcp. */
  else if (embedded_protocol == ip_protocol_tcp)
  {
    sr_tcp_hdr_t *double_embedded_tcp_hdr = (sr_tcp_hdr_t *) embedded_ip_payload;
    if (is_external_if(interface))
      double_embedded_tcp_hdr->tcp_src_port = port;
    if (is_internal_if(interface))
      double_embedded_tcp_hdr->tcp_dst_port = port;
  }
  else 
  {
    fprintf(stderr, "[FATAL] Unhandled icmp error payload protocol: %d\n", embedded_protocol);
    return;
  }
 
}

/* TODO what if private to private, public to public!!*/
static void rewrite_icmp_packet_to_forward_for_nat(
    struct sr_instance *sr, 
    sr_ip_hdr_t *ip_hdr, 
    char *interface,
    struct sr_nat_mapping *mapping) 
{
  printf("======> rewriting icmp packet\n");
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(((uint8_t *)ip_hdr) + ip_hdr_len);
  sr_ip_hdr_t *embedded_ip_hdr = NULL;

  /****** Outgoing ******/
  if (is_internal_if(interface)) 
  {
    printf("======> is internal interface\n");
    ip_hdr->ip_src = mapping->ip_ext;

    if (is_request_query_icmp_packet(icmp_hdr) || 
        is_reply_query_icmp_packet(icmp_hdr))
    {
      ((sr_icmp_full_hdr_t *)icmp_hdr)->icmp_seq_num = mapping->aux_ext;
    }
    else if (is_error_icmp_packet(icmp_hdr))
    {
      embedded_ip_hdr = (sr_ip_hdr_t *)(((uint8_t *)icmp_hdr) + ICMP_HDR_FULL_LEN);
      embedded_ip_hdr->ip_dst = mapping->ip_ext;
      rewrite_icmp_error_packet_port_for_nat(embedded_ip_hdr, mapping->aux_ext, interface);
    }
    else 
    {
      fprintf(stderr, "[FATAL] unhandled icmp type: %d, code: %d\n", 
                  icmp_hdr->icmp_type, icmp_hdr->icmp_code);
      return;
    }
  }
  /****** Incoming ******/
  else if (is_external_if(interface))
  {
    printf("======> is external interface\n");
    ip_hdr->ip_dst = mapping->ip_int;
    if (is_request_query_icmp_packet(icmp_hdr) || 
        is_reply_query_icmp_packet(icmp_hdr)) 
    {
      ((sr_icmp_full_hdr_t *)icmp_hdr)->icmp_seq_num = mapping->aux_int;
    }
    else if (is_error_icmp_packet(icmp_hdr))
    {
      embedded_ip_hdr = (sr_ip_hdr_t *)(((uint8_t *)icmp_hdr) + ICMP_HDR_FULL_LEN);
      embedded_ip_hdr->ip_src = mapping->ip_int;
      rewrite_icmp_error_packet_port_for_nat(embedded_ip_hdr, mapping->aux_int, interface);
    }
    else 
    {
      fprintf(stderr, "[FATAL] Unhandled icmp type: %d, code: %d\n", 
                  icmp_hdr->icmp_type, icmp_hdr->icmp_code);
      return;
    }
  }
  
  /* Recompute embedded header cksum for icmp error messages */
  if (NULL != embedded_ip_hdr)
  {
    uint32_t embedded_ip_hdr_len = embedded_ip_hdr->ip_hl * sizeof(uint32_t);
    embedded_ip_hdr->ip_sum = 0;
    embedded_ip_hdr->ip_sum = cksum(embedded_ip_hdr, embedded_ip_hdr_len);  
  }
  
  /* Recompute icmp header cksum */
  uint32_t ip_len = ntohs(ip_hdr->ip_len);

  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ip_len - ip_hdr_len);
}

static void create_pseudo_tcp_header_and_calculate_checksum(sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr)
{
  uint32_t ip_len = ntohs(ip_hdr->ip_len);
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  uint16_t tcp_seg_len = ip_len - ip_hdr_len;
  uint32_t pseudo_hdr_len = 4 * 3 + tcp_seg_len;

  uint8_t *pseudo_hdr = (uint8_t *)malloc(pseudo_hdr_len);
  uint8_t *offset = pseudo_hdr;

  memset(offset, ip_hdr->ip_src, sizeof(uint32_t));
  offset +=  sizeof(uint32_t);
  memset(offset, ip_hdr->ip_dst, sizeof(uint32_t));
  offset +=  sizeof(uint32_t);

  memset(offset, 0, sizeof(uint8_t));
  offset +=  sizeof(uint8_t);
  memset(offset, ip_hdr->ip_p, sizeof(uint8_t));
  offset +=  sizeof(uint8_t);
  memset(offset, htons(tcp_seg_len), sizeof(uint16_t));
  offset +=  sizeof(uint16_t);

  tcp_hdr->tcp_sum = 0;
  memcpy(offset, (uint8_t *)tcp_hdr, tcp_seg_len);

  tcp_hdr->tcp_sum = cksum(pseudo_hdr, pseudo_hdr_len);
  free(pseudo_hdr);
}

static void rewrite_tcp_packet_to_forward_for_nat(
    struct sr_instance *sr, 
    sr_ip_hdr_t *ip_hdr, 
    char *incoming_if,
    struct sr_nat_mapping *mapping,
    uint8_t *to_send)
{
  printf("======> rewriting tcp packet\n");
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(to_send + ETHER_HDR_LEN + ip_hdr_len);
  
  if (is_internal_if(incoming_if))
  {
    ip_hdr->ip_src = mapping->ip_ext;
    tcp_hdr->tcp_src_port = mapping->aux_ext;
  }
  else if(is_external_if(incoming_if))
  {
    ip_hdr->ip_dst = mapping->ip_int;
    tcp_hdr->tcp_dst_port = mapping->aux_int;
  }

  /* Recomputer the tcp header cksum */
  create_pseudo_tcp_header_and_calculate_checksum(ip_hdr, tcp_hdr);
}

void rewrite_ip_packet_to_forward_for_nat(
    struct sr_instance *sr, 
    uint8_t *to_send, 
    char *incoming_if,
    struct sr_nat_mapping *mapping) 
{
  printf("======> rewriting ip packet\n");
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(to_send + ETHER_HDR_LEN);
  uint8_t protocol = ip_hdr->ip_p;
  if (protocol == ip_protocol_icmp) 
  {
    rewrite_icmp_packet_to_forward_for_nat(sr, ip_hdr, incoming_if, mapping);
  }
  else if (protocol == ip_protocol_tcp) 
  {
    rewrite_tcp_packet_to_forward_for_nat(sr, ip_hdr, incoming_if, mapping, to_send);
  }
  
  /* Recompute the outer IP header cksum */
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);
}

void sr_arp_lookup_and_send_with_nat( /* TODO, in handle arp, choose one to use.*/
    struct sr_instance *sr, 
    uint8_t *to_send, 
    unsigned int to_send_len, 
    uint32_t next_hop_ip, 
    char *next_hop_if,
    char *incoming_if,
    struct sr_nat_mapping *mapping) 
{
  struct sr_arpentry *arp = sr_arpcache_lookup(&sr->cache, next_hop_ip); 

  if (NULL != arp) 
  {
    rewrite_ip_packet_to_forward_for_nat(sr, to_send, incoming_if, mapping);
    sr_nat_destroy_mapping_helper(mapping);
    sr_send_packet_wrapper(sr, to_send, to_send_len, next_hop_if, 
                     sr_get_interface(sr, next_hop_if)->addr, arp->mac, true);
    free(arp);
  } 
  else 
  {
    struct sr_arpreq * req = 
           sr_arpcache_queuereq_with_nat(&sr->cache, next_hop_ip, /* TODO */
                       (uint8_t *)to_send, to_send_len, next_hop_if, incoming_if, mapping);
    handle_arpreq(req, sr);
  }
}

void sr_arp_lookup_and_send(
    struct sr_instance *sr, 
    uint8_t *to_send, 
    unsigned int to_send_len, 
    uint32_t next_hop_addr, 
    char *if_name) 
{
  struct sr_arpentry *arp = sr_arpcache_lookup(&sr->cache, next_hop_addr); 
  if (NULL != arp) 
  {
    sr_send_packet_wrapper(sr, to_send, to_send_len, if_name, sr_get_interface(sr, if_name)->addr, arp->mac, true);
    free(arp);
  } 
  else 
  {
    struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, next_hop_addr, (uint8_t *)to_send, to_send_len, if_name);
    handle_arpreq(req, sr);
  }
}

void sr_handle_arp_packet(
        struct sr_instance *sr,
        sr_ethernet_hdr_t *ether_hdr,
        uint8_t * packet/* lent */,
        unsigned int len/* length of the ethernet payload */,
        char* interface/* lent */)
{
  
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) packet;
  struct sr_if *sr_interface;
  /*check if the arp packet is for me*/
  for (sr_interface = sr->if_list; sr_interface != NULL; sr_interface = sr_interface->next){
    if (arp_hdr->ar_tip == sr_interface->ip){ /* interface IPs are in network order! */
      if(arp_op_request == ntohs(arp_hdr->ar_op)){
        send_arp_reply(sr, ether_hdr, packet, sr_interface);
        return;
      }
      else if (arp_op_reply == ntohs(arp_hdr->ar_op)){
        sr_handle_arp_reply(sr, packet);
        return;
      }
      else{
        fprintf(stderr, "It's an arp packet for me but neither a request nor reply\n");
        return;
      }
    }
  }
  fprintf(stderr, "This arp packet is not for me\n");
}

void sr_create_ip_packet(
        struct sr_instance *sr,
        unsigned int len,
        sr_ip_hdr_t *ip_hdr,
        uint8_t **new_ip_pkt,
        unsigned int *new_len) 

{

  sr_ethernet_hdr_t new_ether_hdr;
  /*memcpy(new_ether_hdr.ether_shost, src_mac, ETHER_ADDR_LEN);*/
  /* memcpy(new_ether_hdr.ether_dhost, dst_mac, ETHER_ADDR_LEN); */
  new_ether_hdr.ether_type = htons(ethertype_ip);  

  /* Directly operate on old ip header */
  
  uint8_t *buf = malloc(len); /*freed later!*/
  uint8_t *offset = buf;
  memcpy(offset, &new_ether_hdr, ETHER_HDR_LEN);
  offset += ETHER_HDR_LEN;

  uint32_t ip_len = ntohs(ip_hdr->ip_len) ;
  uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);

  memcpy(offset, (uint8_t *)ip_hdr, ip_len);
  uint8_t ttl = ip_hdr->ip_ttl;
  ((sr_ip_hdr_t *)offset)->ip_ttl = ttl - 1;
  ((sr_ip_hdr_t *)offset)->ip_sum = 0;
  ((sr_ip_hdr_t *)offset)->ip_sum = cksum(offset, ip_hdr_len);
  *new_ip_pkt = buf;
  *new_len = len;
  /* sr_send_packet(sr, buf, len, sr_get_if_name(sr, new_ether_hdr.ether_shost)); */
  /*total size is the size including the ethernet header*/
  /* free(buf); */
}

static void cpy_hdrs(
                uint8_t **dest, 
                sr_ethernet_hdr_t * ether_hdr, 
                sr_ip_hdr_t * ip_hdr, 
                sr_icmp_hdr_t * icmp_hdr) 
{
      memcpy(*dest, ether_hdr, sizeof(sr_ethernet_hdr_t));
      (*dest) += sizeof(sr_ethernet_hdr_t);
      memcpy(*dest, ip_hdr, sizeof(sr_ip_hdr_t));
      (*dest) += sizeof(sr_ip_hdr_t);
      memcpy(*dest, icmp_hdr, sizeof(sr_icmp_hdr_t));
      (*dest) += sizeof(sr_icmp_hdr_t);
}

void sr_create_icmp_packet(
        struct sr_instance *sr,
        sr_ethernet_hdr_t *ether_hdr,
        sr_ip_hdr_t *ip_hdr,
        icmp_kind_t icmp_kind,
        uint8_t **new_icmp_packet,
        unsigned int *new_len) 
{
  sr_ethernet_hdr_t new_ether_hdr;
  
  /*memcpy(new_ether_hdr.ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);*/
  /*memcpy(new_ether_hdr.ether_shost, ether_hdr->ether_dhost, ETHER_ADDR_LEN);*/
  new_ether_hdr.ether_type = htons(ethertype_ip);  

  sr_ip_hdr_t new_ip_hdr;
  /* https://en.wikipedia.org/wiki/IPv4 */
  /* https://en.wikipedia.org/wiki/Time_to_live#cite_note-1 */
  new_ip_hdr.ip_hl = 5; /* default 5 words.*/
  new_ip_hdr.ip_v = 4; /* 4 for ipv4. */
  new_ip_hdr.ip_tos = 0; /* 0 for ICMP */
  new_ip_hdr.ip_len = 0; /* to complete later, Length of entire packet */
  new_ip_hdr.ip_id = 0;  /* htons(0) not used, give a random value. https://tools.ietf.org/html/rfc6864 */
  new_ip_hdr.ip_off = htons(0b0100000000000000); /*http://stackoverflow.com/questions/15999739/ip-fragmentation-and-reassembly */
  new_ip_hdr.ip_ttl = 100; /* Recommended default is 64 */	    
  new_ip_hdr.ip_p = 1; /* 1 for ICMP */	    
  new_ip_hdr.ip_sum = 0; /* to complete later*/ 
  new_ip_hdr.ip_src = sr_get_if_ip(sr, ether_hdr->ether_dhost);
  new_ip_hdr.ip_dst = ip_hdr->ip_src;

  /* https://tools.ietf.org/html/rfc792 */
  sr_icmp_hdr_t new_icmp_hdr;
  switch (icmp_kind) {
    case ECHO_REPLY: 
      new_icmp_hdr.icmp_type = 0;
      new_icmp_hdr.icmp_code = 0;  
      new_ip_hdr.ip_id = ip_hdr->ip_id;  /* htons(0) not used, give a random value. https://tools.ietf.org/html/rfc6864 */
      new_ip_hdr.ip_src = ip_hdr->ip_dst;
      break; 
    case TIME_EXCEEDED: 
      new_icmp_hdr.icmp_type = 11;
      new_icmp_hdr.icmp_code = 0;  
      break;
    case PORT_UNREACHABLE: 
      new_icmp_hdr.icmp_type = 3;
      new_icmp_hdr.icmp_code = 3;  
      new_ip_hdr.ip_src = ip_hdr->ip_dst;
      break;
    case NETWORK_UNREACHABLE: 
      new_icmp_hdr.icmp_type = 3;
      new_icmp_hdr.icmp_code = 0;  
      break;
    case HOST_UNREACHABLE:
      new_icmp_hdr.icmp_type = 3;
      new_icmp_hdr.icmp_code = 1;
      uint32_t next_hop_addr; char *if_name; /* next hop addr is in NBO */
      if (0 != longest_prefix_match(sr, ip_hdr->ip_dst, &next_hop_addr, &if_name)) 
      {
        fprintf(stderr, "Dest IP not found for host unreachable\n");
      }
       
      new_ip_hdr.ip_src = sr_get_interface(sr, if_name)->ip;
      break;
  }
  new_icmp_hdr.icmp_sum = 0; /*cksum(&new_icmp_hdr, 2);*/

  uint8_t *buf, *offset;
  int new_ether_frame_len, new_ip_datagram_len, new_icmp_payload_len;
  int ip_datagram_len = ntohs(ip_hdr->ip_len),
      ip_hdr_len      = ip_hdr->ip_hl * sizeof(uint32_t);
  switch (icmp_kind) {
    case ECHO_REPLY: {
 
      /* This 16-bit field defines the entire packet size, including header and data, in bytes. */
      new_ether_frame_len = ETHER_HDR_LEN + ip_datagram_len;
      offset = buf = malloc(new_ether_frame_len); 
      cpy_hdrs(&offset, &new_ether_hdr, &new_ip_hdr, &new_icmp_hdr);

      /* The second field (4 bits) is the Internet Header Length (IHL), which is the number of 32-bit words in the header. */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(((uint8_t *)ip_hdr) + ip_hdr_len); /* Point arith! */

      /*if (0 == icmp_hdr->icmp_code) */
      /*  memset(offset, 0, sizeof(uint32_t)); */
      /* else */ 
      memcpy(offset, ((uint8_t *)icmp_hdr) + ICMP_HDR_LEN, sizeof(uint32_t));
      offset += sizeof(uint32_t);

      uint32_t new_icmp_payload_len = ip_datagram_len - ip_hdr_len - ICMP_HDR_LEN - sizeof(uint32_t);
      memcpy(offset, ((uint8_t *)icmp_hdr) + ICMP_HDR_LEN + sizeof(uint32_t), new_icmp_payload_len);
      break; 
    }  
    case TIME_EXCEEDED: 
    case PORT_UNREACHABLE:
    case HOST_UNREACHABLE: 
    case NETWORK_UNREACHABLE: {

      new_ether_frame_len =   ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + sizeof(uint32_t);
      new_icmp_payload_len = ip_hdr_len + 8;
      new_ether_frame_len += new_icmp_payload_len;
      offset = buf = malloc(new_ether_frame_len); /*to free later!*/
      cpy_hdrs(&offset, &new_ether_hdr, &new_ip_hdr, &new_icmp_hdr);

      memset(offset, 0, sizeof(uint32_t));
      offset += sizeof(uint32_t);
      ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);
      memcpy(offset, ip_hdr, new_icmp_payload_len);
    
      break;
    }
  }
  
  new_ip_datagram_len = new_ether_frame_len - ETHER_HDR_LEN;

  /* fill in IP datagram length */
  sr_ip_hdr_t *new_ip_hdr_cpy = (sr_ip_hdr_t *)(buf + ETHER_HDR_LEN);
  new_ip_hdr_cpy->ip_len = htons(new_ip_datagram_len);

  /* create checksum for ICMP */
  sr_icmp_hdr_t *new_icmp_hdr_cpy = (sr_icmp_hdr_t *)(buf + ETHER_HDR_LEN + IP_HDR_LEN);
  new_icmp_hdr_cpy->icmp_sum = cksum(new_icmp_hdr_cpy, new_ip_datagram_len - IP_HDR_LEN);

  /* create checksum for IP */
  new_ip_hdr_cpy->ip_sum = cksum(new_ip_hdr_cpy, IP_HDR_LEN);

  *new_icmp_packet = buf;
  *new_len = new_ether_frame_len;
  /* pass in source mac because in sending packet they make sure the interface is included in iflist*/
  /* sr_send_packet(sr, buf, new_ether_frame_len, sr_get_if_name(sr, new_ether_hdr.ether_shost)); */
  /*total size is the size including the ethernet header*/
  /* free(buf); */
}


void sr_send_packet_wrapper(struct sr_instance* sr, uint8_t* buf, unsigned int len, const char* ifname, unsigned char src_mac[ETHER_ADDR_LEN], unsigned char dst_mac[ETHER_ADDR_LEN], bool should_free) 
{
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)buf;
  memcpy(ether_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  sr_send_packet(sr, buf, len, (ifname == NULL) ? sr_get_if_name(sr, ether_hdr->ether_shost) : ifname); 
  if (should_free) free(buf); 
}
