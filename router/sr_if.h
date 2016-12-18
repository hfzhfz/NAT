/*-----------------------------------------------------------------------------
 * file:  sr_if.h
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handeling interfaces
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#include <stdbool.h>
#include "sr_protocol.h"

struct sr_instance;

/* ----------------------------------------------------------------------------
 * struct sr_if
 *
 * Node in the interface list for each router
 *
 * -------------------------------------------------------------------------- */
extern const char *internal_if;
extern const char *external_if;

struct sr_if
{
  char name[sr_IFACE_NAMELEN];
  unsigned char addr[ETHER_ADDR_LEN];
  uint32_t ip;
  uint32_t speed;
  struct sr_if* next;
};
bool is_internal_if(char *interface);
bool is_external_if(char *interface);
bool sr_contains_ip(struct sr_instance* sr, uint32_t ip);
char* sr_get_if_name(struct sr_instance* sr, const unsigned char *eth_addr);
uint32_t sr_get_if_ip(struct sr_instance* sr, const unsigned char *eth_addr);
struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name);
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t ip_nbo);
void sr_print_if_list(struct sr_instance*);
void sr_print_if(struct sr_if*);

#endif /* --  sr_INTERFACE_H -- */
