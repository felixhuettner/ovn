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

#ifndef ROUTE_H
#define ROUTE_H 1

#include <stdbool.h>
#include <netinet/in.h>
#include "openvswitch/hmap.h"
#include "sset.h"
#include "simap.h"

struct hmap;
struct ovsdb_idl_index;
struct sbrec_chassis;
struct sbrec_port_binding;
struct sset;

struct route_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_load_balancer_table *lb_table;
    const struct sbrec_chassis *chassis;
    const struct sset *active_tunnels;
    struct hmap *local_datapaths;
    struct hmap *local_lbs;
    const struct sset *local_lports;
    struct ovsdb_idl_index *sbrec_route_by_datapath;
};

struct route_ctx_out {
    struct hmap *tracked_re_datapaths;
    /* Contains struct advertise_datapath_entry */
    struct hmap *announce_routes;
};

struct advertise_datapath_entry {
    struct hmap_node node;
    int64_t key; // tunnel_key of the datapath
    const struct sbrec_datapath_binding *db;
    bool maintain_vrf;
    bool use_netns;
    struct hmap routes;
    /* the name of the port bindings locally bound for this datapath and
     * running route exchange logic.
     * The key is the port name and the value is the ifindex if set. */
    struct simap bound_ports;
};

struct advertise_route_entry {
    struct hmap_node node;
    struct in6_addr addr;
    unsigned int plen;
    unsigned int priority;
    /* used by the route-exchange module to determine if the route is
     * already installed */
    bool installed;
};

bool route_exchange_relevant_port(const struct sbrec_port_binding *pb);
uint32_t advertise_route_hash(const struct in6_addr *dst, unsigned int plen);
void route_run(struct route_ctx_in *,
               struct route_ctx_out *);
void route_cleanup(struct hmap *announce_routes);

#endif /* ROUTE_H */
