
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "sr_protocol.h"

#define MAX_PORT 65335
#define MIN_PORT 1024

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  CLOSED,
  LISTEN,
  SYN_SENT,
  SYN_SENT_SYNACK_RCVD,
  SYN_SENT_SYN_RCVD,
  SYN_RCVD,
  ESTAB,
  ESTAB_FIN_RCVD,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSING,
  CLOSE_WAIT,
  LAST_ACK,
  TIME_WAIT
} sr_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_endpoint;
  sr_tcp_state tcp_state; 
  time_t last_updated; /* use to timeout mappings */
  uint32_t seq_num_private;
  uint32_t seq_num_public;

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

typedef struct syn_pkt {
  uint8_t *packet;
  unsigned int len;
  time_t time_inserted;
  struct syn_pkt *next;
} syn_pkt_t;

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;

  /* -I INTEGER -- ICMP query timeout interval in seconds (default to 60)    */
  /* -E INTEGER -- TCP Established Idle Timeout in seconds (default to 7440) */
  /* -R INTEGER -- TCP Transitory Idle Timeout in seconds (default to 300)   */ 
  uint32_t icmp_query_timeout;
  uint32_t tcp_estab_idle_timeout;
  uint32_t tcp_trans_idle_timeout;
  uint32_t syn_timeout;
 
  bool *port_map; /* indicates if each port is avaiable or not: TRUE avail, FALSE not avail. */
  uint16_t last_avail_port;

  syn_pkt_t *syn_pkt_cache;  
  struct sr_instance *sr;

  /* in NBO */
  uint32_t external_ip;
};


int   sr_nat_init(struct sr_nat *, uint32_t, uint32_t, uint32_t);     /* Initializes the nat */
void sr_nat_destroy_mapping_helper(struct sr_nat_mapping *mapping);
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

struct sr_nat_mapping *sr_nat_lookup_external_for_tcp(struct sr_nat *nat,
    uint16_t aux_ext, uint32_t ip_endpoint, struct sr_nat_connection ** conn);
 
struct sr_nat_mapping *sr_nat_lookup_internal_for_tcp(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, uint32_t ip_endpoint, struct sr_nat_connection ** conn);
 
/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* This is to ensure atomicity */
struct sr_nat_mapping *sr_nat_insert_conn_and_mapping_if_not_exist(struct sr_nat *nat,
  uint32_t ip_int, uint32_t aux_int, sr_nat_mapping_type type, struct sr_nat_connection *conn);

/* This is to ensure atomicity */
bool sr_nat_update_conn_insert_if_not_exist(struct sr_nat *nat,
  uint32_t ip_int, uint32_t aux_int, sr_nat_mapping_type type, struct sr_nat_connection *conn);

bool sr_nat_insert_conn(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_connection *conn);

bool sr_nat_update_conn(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_connection *conn);

void sr_nat_cache_syn(struct sr_nat *nat, uint8_t *packet, unsigned int len);

/* Deletes all BUT LAST ONE of the syn packets in the cache that match the endpoint IP and TCP port, but only return one of them. Endpoint ip and port are in NBO. Need to FREE the returned packet!! */
syn_pkt_t *delete_syn_pkt(struct sr_nat *nat, uint32_t ip_endpoint, uint16_t port_endpoint);

void tcp_state_machine(struct sr_nat *nat, sr_tcp_hdr_t *tcp_hdr, struct sr_nat_connection *conn, char* interface);

void print_mapping_helper(struct sr_nat_mapping *mapping);
#endif
