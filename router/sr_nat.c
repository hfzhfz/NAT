#include <netinet/in.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_router.h" 

/* Assumes an available port can always be found. */
/* Port number will be in NBO */
static bool get_an_avail_port(struct sr_nat *nat, uint16_t *port) /* TODO can this be accessed concurrently? */ 
{
  bool end_hit = false;
  while (!nat->port_map[nat->last_avail_port]) 
  {
    if (MAX_PORT == nat->last_avail_port) 
    {
      if (end_hit) return false;
      end_hit = true;
      nat->last_avail_port = MIN_PORT;
    }
    else 
    {
      nat->last_avail_port ++;
    }
  }

  assert(true == nat->port_map[nat->last_avail_port]);
  nat->port_map[nat->last_avail_port] = false;
  (*port) = htons(nat->last_avail_port);
  return true;
}

int sr_nat_init(
    struct sr_nat *nat, 
    uint32_t icmp_query_timeout,
    uint32_t tcp_estab_idle_timeout,
    uint32_t tcp_trans_idle_timeout
   ) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL; /*TODO*/
  /* Initialize any variables here */
  nat->icmp_query_timeout = icmp_query_timeout;
  nat->tcp_estab_idle_timeout = tcp_estab_idle_timeout;
  nat->tcp_trans_idle_timeout = tcp_trans_idle_timeout;
  nat->syn_timeout = 6;
  nat->port_map = (bool *)malloc(sizeof(bool) * 65336);
  int i;
  for (i = 0; i < MIN_PORT; i++) nat->port_map[i] = false;
  for (i = MIN_PORT; i <= MAX_PORT; i++) nat->port_map[i] = true;
  nat->last_avail_port = MIN_PORT;
  
  nat->syn_pkt_cache = NULL;
  nat->external_ip = 0;
  return success;
}

void sr_nat_destroy_mapping_helper(struct sr_nat_mapping *mapping)
{
  if (NULL == mapping) return;
  struct sr_nat_connection *curr = mapping->conns;

  while (NULL != curr) 
  {
    struct sr_nat_connection *tmp = curr;
    curr = curr->next;
    free(tmp);
  }

  mapping->conns = NULL;
  mapping->next = NULL;
  free(mapping);
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *curr = nat->mappings; 
  while (NULL != curr) {
    struct sr_nat_mapping *tmp = curr;
    curr = curr->next; 
    sr_nat_destroy_mapping_helper(tmp);
  }
  nat->mappings = NULL; /*TODO*/

  free(nat->port_map);

  syn_pkt_t *curr_syn = nat->syn_pkt_cache; 
  while (NULL != curr_syn) {
    syn_pkt_t *tmp = curr_syn;
    curr_syn = curr_syn->next; 
    tmp->next = NULL;
    free(tmp->packet);
    free(tmp);
  }
  nat->syn_pkt_cache = NULL;

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

static void sr_nat_timeout_conns_helper(struct sr_nat *nat, struct sr_nat_mapping *mapping, time_t curtime) {  /* Periodic Timout handling */

  struct sr_nat_connection *curr = mapping->conns;
  struct sr_nat_connection *prev = NULL;

  while (NULL != curr)
  {
    bool delete_curr = false;
    if (ESTAB == curr->tcp_state)
    {
      if (difftime(curtime, curr->last_updated) >= (double)nat->tcp_estab_idle_timeout) /* FIXME: >= / > */
        delete_curr = true;
    }
    else 
    {
      if (difftime(curtime, curr->last_updated) >= (double)nat->tcp_trans_idle_timeout) /* FIXME: >= / > */
        delete_curr = true;
    }
   
    if (delete_curr) 
    { 
      if (NULL == prev) mapping->conns = curr->next;
      else prev->next = curr->next;
      
      struct sr_nat_connection *tmp = curr;
      curr = curr->next;
      tmp->next = NULL;
      free(tmp);
    }
    else 
    {
      prev = curr;
      curr = curr->next;
    }
  }
}


static void sr_nat_timeout_mapping_helper(struct sr_nat *nat, time_t curtime) {  /* Periodic Timout handling */
  
  struct sr_nat_mapping *curr = nat->mappings;
  struct sr_nat_mapping *prev = NULL;

  while (NULL != curr)
  {
    bool delete_curr = false;
    if (nat_mapping_icmp == curr->type)
    {
      if (difftime(curtime, curr->last_updated) >= (double)nat->icmp_query_timeout) /* FIXME: >= / > */
        delete_curr = true;
    }
    else if (nat_mapping_tcp == curr->type)
    {
      sr_nat_timeout_conns_helper(nat, curr, curtime);
      if (NULL == curr->conns) /* FIXME: Make sure we are not deleting whats just added? */
        delete_curr = true;
    }
    else 
    {
      printf("[warn] unrecognized nat mapping type!\n");
    }
   
    if (delete_curr) 
    { 
      if (NULL == prev) nat->mappings = curr->next;
      else prev->next = curr->next;
      
      struct sr_nat_mapping *tmp = curr;
      curr = curr->next;
      /* Free up the port. */
      nat->port_map[ntohs(tmp->aux_ext)] = true; 
      sr_nat_destroy_mapping_helper(tmp);
    }
    else 
    {
      prev = curr;
      curr = curr->next;
    }
  }
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat *nat = (struct sr_nat *)nat_ptr; 
    time_t curtime = time(NULL);

    /* check for nat mapping timeouts */    
    sr_nat_timeout_mapping_helper(nat, curtime);  
  
    /* check for cached syn packet timeouts */    
    syn_pkt_t *curr = nat->syn_pkt_cache;
    syn_pkt_t *prev = NULL;

    while (NULL != curr)
    {
      printf("====> [UNSOLICITED SYN] iterating through syn packets.\n");
      if (difftime(curtime, curr->time_inserted) >= (double)nat->syn_timeout)
      {
        printf("====> [UNSOLICITED SYN] TIMEOUT.\n");
        if (NULL == prev) nat->syn_pkt_cache = curr->next;
        else prev->next = curr->next;

        syn_pkt_t *tmp = curr;
        curr = curr->next;

        /* Send ICMP port unreachable, type = 3, code = 3*/
        uint8_t *packet = tmp->packet;
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETHER_HDR_LEN);
        uint8_t *to_send; unsigned int to_send_len;
        sr_create_icmp_packet(nat->sr, ether_hdr, ip_hdr, PORT_UNREACHABLE, &to_send, &to_send_len);
        sr_send_icmp(nat->sr, to_send, to_send_len);
 
        free(tmp->packet);
        tmp->next = NULL;
        free(tmp); 
      } 
      else 
      {
        prev = curr;
        curr = curr->next;        
      }
    }
    
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

static void copy_conn_helper(struct sr_nat_connection *to, struct sr_nat_connection *from)
{
  to->ip_endpoint = from->ip_endpoint;
  to->tcp_state = from->tcp_state;
  to->last_updated = from->last_updated;
  to->seq_num_private = from->seq_num_private;
  to->seq_num_public = from->seq_num_public;
  to->next = NULL;
}

static void copy_mapping_helper(struct sr_nat_mapping *to, struct sr_nat_mapping *from)
{
  to->type = from->type;
  to->ip_int = from->ip_int;
  to->ip_ext = from->ip_ext;
  to->aux_int = from->aux_int;
  to->aux_ext = from->aux_ext; 
  to->last_updated = from->last_updated;

  to->conns = NULL;
  struct sr_nat_connection *to_curr_conn = NULL;
  struct sr_nat_connection *to_curr_conn_prev = NULL;
  struct sr_nat_connection *from_curr_conn = from->conns;

  while (NULL != from_curr_conn)
  {
    to_curr_conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
    copy_conn_helper(to_curr_conn, from_curr_conn);
    if (NULL == to_curr_conn_prev) to->conns = to_curr_conn;
    else to_curr_conn_prev->next = to_curr_conn;
    to_curr_conn_prev = to_curr_conn;
    from_curr_conn = from_curr_conn->next;
  }

  to->next = NULL;
}

/* This method does not make a copy! */
static struct sr_nat_connection *sr_conn_lookup_helper(struct sr_nat_mapping *mapping, uint32_t ip_endpoint)
{
 
  struct sr_nat_connection *curr = mapping->conns;
  while (NULL != curr)
  {
    if (curr->ip_endpoint == ip_endpoint)
    {
      return curr;
    } 
    curr = curr->next;      
  }
  return NULL;
}

struct sr_nat_mapping *sr_nat_lookup_external_for_tcp(struct sr_nat *nat,
    uint16_t aux_ext, uint32_t ip_endpoint, struct sr_nat_connection **conn) {
  /* Returned mapping is a copy */
  struct sr_nat_mapping *mapping = sr_nat_lookup_external(nat, aux_ext, nat_mapping_tcp);
  if (NULL == mapping) return NULL;
  
  (*conn) = sr_conn_lookup_helper(mapping, ip_endpoint);
  return mapping;
}

struct sr_nat_mapping *sr_nat_lookup_internal_for_tcp(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, uint32_t ip_endpoint, struct sr_nat_connection **conn) {
  /* Returned mapping is a copy */
  struct sr_nat_mapping *mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, nat_mapping_tcp);
  if (NULL == mapping) return NULL;
  
  (*conn) = sr_conn_lookup_helper(mapping, ip_endpoint);
  return mapping;
}

/* This method does not make a copy! */
static struct sr_nat_mapping *sr_nat_lookup_external_helper(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type) {

  struct sr_nat_mapping *curr = nat->mappings; 
  while (NULL != curr) {
    if (aux_ext == curr->aux_ext)
    {
      /* External port numbers are unique. */
      assert(type == curr->type);
      curr->last_updated = time(NULL);
      return curr;
    }
    curr = curr->next; 
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type) {

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping *copy = NULL;
  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *result = sr_nat_lookup_external_helper(nat, aux_ext, type);
  if (NULL != result) 
  {
    copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    copy_mapping_helper(copy, result);
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* This method does not make a copy! */
static struct sr_nat_mapping *sr_nat_lookup_internal_helper(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  struct sr_nat_mapping *curr = nat->mappings; 
  while (NULL != curr) {
    if (ip_int == curr->ip_int &&
        aux_int == curr->aux_int &&
        type == curr->type)
    {
      curr->last_updated = time(NULL);
      /* External port numbers are unique. */
      return curr;
    }
    curr = curr->next; 
  }

  return NULL;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping *copy = NULL;

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *result = sr_nat_lookup_internal_helper(nat, ip_int, aux_int, type);
  if (NULL != result) 
  {
    copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    copy_mapping_helper(copy, result);
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void print_mapping_helper(struct sr_nat_mapping *mapping) {
 printf("\tis icmp:     %s\n", ((mapping->type == nat_mapping_icmp) ? "true" : "false"));
 printf("\tis tcp:      %s\n", ((mapping->type == nat_mapping_tcp) ? "true" : "false"));
 printf("\tip_int:      %d\n", mapping->ip_int);
 printf("\tip_ext:      %d\n", mapping->ip_ext);
 printf("\taux_int:     %d\n", ntohs(mapping->aux_int));
 printf("\taux_ext:     %d\n", ntohs(mapping->aux_ext));
}
 
/* This method does not make a copy! */
static struct sr_nat_mapping *sr_nat_insert_mapping_helper(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  uint16_t new_port;
  bool success = get_an_avail_port(nat, &new_port); 
  if (!success) {
    printf("[FATAL] no more port available!\n");
    return NULL;
  }

  if (nat->external_ip == 0) 
    nat->external_ip = sr_get_interface(nat->sr, (const char *)external_if)->ip;  
  printf("**** external ip is: %d\n", nat->external_ip);
  mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->external_ip;
  mapping->aux_int = aux_int;
  mapping->aux_ext = new_port;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL; /* TODO for TCP*/
  mapping->next = NULL;

  if (NULL == nat->mappings)
  {
    nat->mappings = mapping;
  }
  else 
  {
    struct sr_nat_mapping *curr = nat->mappings;
    while (NULL != curr->next) curr = curr->next;
    curr->next = mapping;
  }

  return mapping;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
   FIXME: This method assumes the mapping DOESN't ALREADY EXIST!
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *result = sr_nat_insert_mapping_helper(nat, ip_int, aux_int, type);

  if (NULL != result)
  {
    copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    copy_mapping_helper(copy, result);
  }
  pthread_mutex_unlock(&(nat->lock));

  return copy;
}

static void sr_nat_insert_conn_helper(struct sr_nat_mapping *mapping, struct sr_nat_connection *conn) {
  struct sr_nat_connection *copy = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
  copy_conn_helper(copy, conn);
  copy->last_updated = time(NULL);

  struct sr_nat_connection *curr = mapping->conns;
  if (NULL == curr) 
  {
    mapping->conns = copy;
  } 
  else 
  {
    while (NULL != curr->next)
    {
      curr = curr->next;
    }
    curr->next = copy;
  }
}

struct sr_nat_mapping *sr_nat_insert_conn_and_mapping_if_not_exist(struct sr_nat *nat,
  uint32_t ip_int, uint32_t aux_int, sr_nat_mapping_type type, struct sr_nat_connection *conn) {

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = sr_nat_lookup_internal_helper(nat, ip_int, aux_int, type);
  if (NULL == mapping)
  {
    printf("[warn] nat mapping does not exist for internal port: %d, and internal ip: %d!\n", aux_int, ip_int);
    mapping = sr_nat_insert_mapping_helper(nat, ip_int, aux_int, type);
    if (NULL == mapping) goto exit;
  }

  if (NULL != sr_conn_lookup_helper(mapping, conn->ip_endpoint)) 
  {
    printf("[FATAL] connection with endpoint ip %d already exist for external port %d!\n", conn->ip_endpoint, mapping->aux_ext);
    goto exit;
  }

  sr_nat_insert_conn_helper(mapping, conn);
 
  copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  copy_mapping_helper(copy, mapping);
  exit: {
    pthread_mutex_unlock(&(nat->lock));
  }

  return copy;

}

bool sr_nat_insert_conn(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_connection *conn) {

  pthread_mutex_lock(&(nat->lock));
  bool ret = false;
  struct sr_nat_mapping *mapping = sr_nat_lookup_external_helper(nat, aux_ext, type);
  if (NULL == mapping)
  {
    printf("[FATAL] nat mapping does not exist for external port %d!\n", aux_ext);
    goto exit;
  }

  if (NULL != sr_conn_lookup_helper(mapping, conn->ip_endpoint)) 
  {
    printf("[FATAL] connection with endpoint ip %d already exist for external port %d!\n", conn->ip_endpoint, aux_ext);
    goto exit;
  }
 
  sr_nat_insert_conn_helper(nat->mappings, conn);

  ret = true;
  exit: {
    pthread_mutex_unlock(&(nat->lock));
  }

  return ret;
}

bool sr_nat_update_conn_insert_if_not_exist(struct sr_nat *nat,
  uint32_t ip_int, uint32_t aux_int, sr_nat_mapping_type type, struct sr_nat_connection *conn) {

  pthread_mutex_lock(&(nat->lock));
  bool ret = false;
  struct sr_nat_mapping *mapping = sr_nat_lookup_internal_helper(nat, ip_int, aux_int, type);
  if (NULL == mapping) 
  {
    printf("[warn] nat mapping does not exist for internal port: %d, and internal ip: %d!\n", aux_int, ip_int);
    mapping = sr_nat_insert_mapping_helper(nat, ip_int, aux_int, type);
    if (NULL == mapping) goto exit;
  }

  struct sr_nat_connection *to_update = sr_conn_lookup_helper(mapping, conn->ip_endpoint);
  if (NULL == to_update) 
  {
    printf("[warn] connection with endpoint ip %d DOES NOT already exist for external port %d!\n", conn->ip_endpoint, mapping->aux_ext);
    sr_nat_insert_conn_helper(nat->mappings, conn);
  }
  else 
  {
    struct sr_nat_connection *orig_next = to_update->next;
    copy_conn_helper(to_update, conn);
    to_update->next = orig_next;
    to_update->last_updated = time(NULL);
  } 

  ret = true;
  exit: {
    pthread_mutex_unlock(&(nat->lock));
  }

  return ret;
}

bool sr_nat_update_conn(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type, struct sr_nat_connection *conn) {

  pthread_mutex_lock(&(nat->lock));
  bool ret = false;
  struct sr_nat_mapping *mapping = sr_nat_lookup_external_helper(nat, aux_ext, type);
  if (NULL == mapping) 
  {
    printf("[FATAL] nat mapping does not exist for external port %d!\n", aux_ext);
    goto exit;
  }

  struct sr_nat_connection *to_update = sr_conn_lookup_helper(mapping, conn->ip_endpoint);
  if (NULL == to_update) 
  {
    printf("[FATAL] connection with endpoint ip %d DOES NOT already exist for external port %d!\n", conn->ip_endpoint, aux_ext);
    goto exit;
  }

  struct sr_nat_connection *orig_next = to_update->next;
  copy_conn_helper(to_update, conn);
  to_update->next = orig_next;
  to_update->last_updated = time(NULL);
  
  ret = true;
  exit: {
    pthread_mutex_unlock(&(nat->lock));
  }

  return ret;
}

/* FIXME: assume each individual syn is cached. */
void sr_nat_cache_syn(struct sr_nat *nat, uint8_t *packet, unsigned int len) {
  pthread_mutex_lock(&(nat->lock));

  syn_pkt_t *syn_pkt = (syn_pkt_t *)malloc(sizeof(syn_pkt_t));  
  syn_pkt->packet = (uint8_t *)malloc(len);
  memcpy(syn_pkt->packet, packet, len);
  syn_pkt->len = len;
  syn_pkt->time_inserted = time(NULL);
  syn_pkt->next = NULL;

  syn_pkt_t *curr = nat->syn_pkt_cache;
  
  if (NULL == curr) 
  {
    nat->syn_pkt_cache = syn_pkt;
  }
  else 
  {
    while (NULL != curr->next) 
    {
      curr = curr->next;
    }
    curr->next = syn_pkt;
  }
  printf("=====> [UNSOLICITED SYN] Cached an Unsolicited SYN.\n");
  pthread_mutex_unlock(&(nat->lock));
}

/* Deletes all BUT LAST ONE of the syn packets in the cache that match the endpoint IP and TCP port, but only return one of them. Endpoint ip and port are in NBO. Need to FREE the returned packet!! */
syn_pkt_t *delete_syn_pkt(struct sr_nat *nat, uint32_t ip_endpoint, uint16_t port_endpoint)
{
  pthread_mutex_lock(&(nat->lock));
  
  syn_pkt_t *match = NULL;

  syn_pkt_t *curr = nat->syn_pkt_cache;
  syn_pkt_t *prev = NULL;

  while (NULL != curr)
  {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(curr->packet);
    uint32_t ip_hdr_len = ip_hdr->ip_hl * sizeof(uint32_t);

    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(((uint8_t *)ip_hdr) + ip_hdr_len);
    
    if (port_endpoint == tcp_hdr->tcp_src_port && ip_endpoint == ip_hdr->ip_src)
    {
      if (NULL == prev) nat->syn_pkt_cache = curr->next;
      else prev->next = curr->next;

      if (NULL == match) 
      {
        match = curr;
      } 
      else 
      {
        free(match->packet);
        free(match);
        match = curr;
      }
    } 
    else 
    {
      prev = curr;
    }

    curr = curr->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return match;
}

void tcp_state_machine(struct sr_nat *nat, sr_tcp_hdr_t *tcp_hdr, struct sr_nat_connection *conn, char* interface){
  switch(conn->tcp_state)
  {
    case CLOSED:
      /* A mapping was found for this tcp connection. */
      if (is_external_if(interface))
      {
        if(tcp_hdr->tcp_syn==1 && tcp_hdr->tcp_ack==0) {
          conn->tcp_state = LISTEN;
          conn->seq_num_public = tcp_hdr->tcp_seq_num;
          break;
        }
      }
      else if (is_internal_if(interface))
      {
        if(tcp_hdr->tcp_syn==1 && tcp_hdr->tcp_ack==0) {
          syn_pkt_t* match = delete_syn_pkt(nat, conn->ip_endpoint, tcp_hdr->tcp_dst_port);
          if (!match) {
            conn->tcp_state = SYN_SENT;
            conn->seq_num_private = tcp_hdr->tcp_seq_num;
            break;
          } else {
            conn->tcp_state = SYN_SENT_SYN_RCVD;
            conn->seq_num_private = tcp_hdr->tcp_seq_num;
            break;
          }
          free(match->packet);
          free(match);
        }
      }
    case LISTEN:
      if (is_internal_if(interface))
      {
        if(tcp_hdr->tcp_ack_num==conn->seq_num_public+1 && tcp_hdr->tcp_syn==1 && tcp_hdr->tcp_ack==1){
          conn->tcp_state = SYN_RCVD;
          conn->seq_num_private = tcp_hdr->tcp_seq_num;
          break;
        }
      }
    case SYN_SENT:
      if (is_external_if(interface))
      {
        if(tcp_hdr->tcp_ack_num==conn->seq_num_private+1 && tcp_hdr->tcp_syn==1 && tcp_hdr->tcp_ack==1){
          conn->tcp_state = SYN_SENT_SYNACK_RCVD;
          conn->seq_num_public = tcp_hdr->tcp_seq_num;
          break;
        }else if(tcp_hdr->tcp_syn==1 && tcp_hdr->tcp_ack==0){
          conn->seq_num_public = tcp_hdr->tcp_seq_num;
          conn->tcp_state = SYN_SENT_SYN_RCVD;
          break;
        }
      }
    case SYN_SENT_SYN_RCVD:
      if (is_internal_if(interface))
      {
        if(tcp_hdr->tcp_ack_num==conn->seq_num_public+1 && tcp_hdr->tcp_ack==1 && tcp_hdr->tcp_syn==1){
          conn->tcp_state = SYN_RCVD;
          conn->seq_num_private = tcp_hdr->tcp_seq_num;
          break;
        }
      }
    case SYN_SENT_SYNACK_RCVD:
      if (is_internal_if(interface))
      {
        if(tcp_hdr->tcp_ack_num==conn->seq_num_public+1 && tcp_hdr->tcp_syn==0 && tcp_hdr->tcp_ack==1){
          conn->tcp_state = ESTAB;
          conn->seq_num_private = tcp_hdr->tcp_seq_num;
          break;
        }
      }
    case SYN_RCVD:
      if(is_external_if(interface)){
        if(tcp_hdr->tcp_ack_num==conn->seq_num_private+1 && tcp_hdr->tcp_syn==0 && tcp_hdr->tcp_ack==1){
          conn->tcp_state = ESTAB;
          conn->seq_num_public = tcp_hdr->tcp_seq_num;
          break;
        }
      }
    case ESTAB:
      if(is_external_if(interface)){
        if(tcp_hdr->tcp_fin==1){
          conn->tcp_state = CLOSED; /*simplified state*/
        }
	break;
      }else if (is_internal_if(interface)){
        if(tcp_hdr->tcp_fin==1){
          conn->tcp_state = CLOSED; /*simplified state*/
        }
	break;
      }
    default:
      break;
   /*   if(is_external_if(interface)){
        conn->seq_num_public = tcp_hdr->tcp_seq_num;
        break;
      }else if (is_internal_if(interface)){
        conn->seq_num_private = tcp_hdr->tcp_seq_num;
        break;
      } */
  }
}
