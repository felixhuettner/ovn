/*
 * Copyright (c) 2024 Canonical
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ROUTE_EXCHANGE_NETLINK_H
#define ROUTE_EXCHANGE_NETLINK_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/hmap.h"
#include <netinet/in.h>

#define RTPROT_OVN 84

struct received_route_node {
    struct hmap_node hmap_node;
    struct in6_addr addr;
    unsigned int plen;
    struct in6_addr nexthop;
};

char * re_nl_get_netns_name(uint32_t table_id);

int re_nl_create_vrf(const char *ifname, uint32_t table_id);
int re_nl_delete_vrf(const char *ifname);

int re_nl_add_route(const char *netns, uint32_t table_id,
                    const struct in6_addr *dst,
                    unsigned int plen, unsigned int priority);
int re_nl_delete_route(const char *netns, uint32_t table_id,
                       const struct in6_addr *dst,
                       unsigned int plen, unsigned int priority);

void re_nl_dump(uint32_t table_id);

void received_routes_destroy(struct hmap *);
void re_nl_sync_routes(uint32_t table_id,
                       const struct hmap *host_routes,
                       struct hmap *learned_routes,
                       bool use_netns);

void re_nl_cleanup_routes(uint32_t table_id, bool use_netns);

#endif /* route-exchange-netlink.h */
