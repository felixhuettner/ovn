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

#include <config.h>

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>

#include "openvswitch/vlog.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "route.h"
#include "route-table-notify.h"
#include "route-exchange.h"
#include "route-exchange-netlink.h"


VLOG_DEFINE_THIS_MODULE(route_exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* While the linux kernel can handle 2^32 routing tables, only so many can fit
 * in the corresponding VRF interface name. */
#define MAX_TABLE_ID 1000000000

#define PRIORITY_DEFAULT 1000
#define PRIORITY_LOCAL_BOUND 100

struct maintained_route_table_entry {
    struct hmap_node node;
    uint32_t table_id;
    bool is_netns;
};

static struct hmap _maintained_route_tables = HMAP_INITIALIZER(
    &_maintained_route_tables);
static struct sset _maintained_vrfs = SSET_INITIALIZER(&_maintained_vrfs);

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_route *sb_route;

    const struct sbrec_datapath_binding *sb_db;
    char *logical_port;
    char *ip_prefix;
    char *nexthop;
    bool stale;
};

static uint32_t
maintained_route_table_hash(uint32_t table_id, bool is_netns)
{
    return hash_boolean(is_netns, hash_int(table_id, 0));
}

static bool
maintained_route_table_contains(uint32_t table_id, bool is_netns)
{
    uint32_t hash = maintained_route_table_hash(table_id, is_netns);
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_WITH_HASH(mrt, node, hash, &_maintained_route_tables) {
        if (mrt->table_id == table_id && mrt->is_netns == is_netns) {
            return true;
        }
    }
    return false;
}

static void
maintained_route_table_add(uint32_t table_id, bool is_netns)
{
    if (maintained_route_table_contains(table_id, is_netns)) {
        return;
    }
    uint32_t hash = maintained_route_table_hash(table_id, is_netns);
    struct maintained_route_table_entry *mrt = xzalloc(sizeof(*mrt));
    mrt->table_id = table_id;
    mrt->is_netns = is_netns;
    hmap_insert(&_maintained_route_tables, &mrt->node, hash);
}

static struct route_entry *
route_alloc_entry(struct hmap *routes,
                  const struct sbrec_datapath_binding *sb_db,
                  const char *logical_port,
                  const char *ip_prefix, const char *nexthop)
{
    struct route_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = xstrdup(logical_port);
    route_e->ip_prefix = xstrdup(ip_prefix);
    route_e->nexthop = xstrdup(nexthop);
    route_e->stale = false;
    uint32_t hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
}

static struct route_entry *
route_lookup_or_add(struct hmap *route_map,
                    const struct sbrec_datapath_binding *sb_db,
                    const char *logical_port, const char *ip_prefix,
                    const char *nexthop)
{
    struct route_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!strcmp(route_e->nexthop, nexthop)) {
            return route_e;
        }
    }

    route_e = route_alloc_entry(route_map, sb_db,
                                 logical_port, ip_prefix, nexthop);
    return route_e;
}

static void
route_erase_entry(struct route_entry *route_e)
{
    free(route_e->logical_port);
    free(route_e->ip_prefix);
    free(route_e->nexthop);
    free(route_e);
}

static void
sb_sync_learned_routes(const struct sbrec_datapath_binding *datapath,
                       const struct hmap *learned_routes,
                       const struct sset *bound_ports,
                       struct ovsdb_idl_txn *ovnsb_idl_txn,
                       struct ovsdb_idl_index *sbrec_route_by_datapath)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    struct route_entry *route_e;
    const struct sbrec_route *sb_route;

    struct sbrec_route *filter =
            sbrec_route_index_init_row(sbrec_route_by_datapath);
    sbrec_route_index_set_datapath(filter, datapath);
    SBREC_ROUTE_FOR_EACH_EQUAL(sb_route, filter, sbrec_route_by_datapath) {
        if (strcmp(sb_route->type, "receive")) {
            continue;
        }
        /* If the port is not local we don't care about it, someone else will */
        if (!sset_contains(bound_ports, sb_route->logical_port)) {
            continue;
        }
        route_e = route_alloc_entry(&sync_routes,
                                    sb_route->datapath,
                                    sb_route->logical_port,
                                    sb_route->ip_prefix,
                                    sb_route->nexthop);
        route_e->stale = true;
        route_e->sb_route = sb_route;
    }
    sbrec_route_index_destroy_row(filter);

    struct received_route_node *learned_route;
    HMAP_FOR_EACH(learned_route, hmap_node, learned_routes) {
        char *ip_prefix = normalize_v46_prefix(&learned_route->addr, learned_route->plen);
        char *nexthop = normalize_v46(&learned_route->nexthop);

        const char *logical_port;
        SSET_FOR_EACH(logical_port, bound_ports) {
            route_e = route_lookup_or_add(&sync_routes,
                datapath,
                logical_port, ip_prefix, nexthop);
            route_e->stale = false;
            if (!route_e->sb_route) {
                sb_route = sbrec_route_insert(ovnsb_idl_txn);
                sbrec_route_set_datapath(sb_route, datapath);
                sbrec_route_set_logical_port(sb_route, logical_port);
                sbrec_route_set_ip_prefix(sb_route, ip_prefix);
                sbrec_route_set_nexthop(sb_route, nexthop);
                sbrec_route_set_type(sb_route, "receive");
                route_e->sb_route = sb_route;
            }
        }
        free(ip_prefix);
        free(nexthop);
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        if (route_e->stale) {
            sbrec_route_delete(route_e->sb_route);
        }
        route_erase_entry(route_e);
    }
    hmap_destroy(&sync_routes);
}

void
route_exchange_run(struct route_exchange_ctx_in *r_ctx_in,
                   struct route_exchange_ctx_out *r_ctx_out)
{
    struct sset old_maintained_vrfs = SSET_INITIALIZER(&old_maintained_vrfs);
    sset_swap(&_maintained_vrfs, &old_maintained_vrfs);
    struct hmap old_maintained_route_table = HMAP_INITIALIZER(
        &old_maintained_route_table);
    hmap_swap(&_maintained_route_tables, &old_maintained_route_table);

    const struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH (ad, node, r_ctx_in->announce_routes) {
        struct hmap received_routes
                = HMAP_INITIALIZER(&received_routes);
        char vrf_name[IFNAMSIZ + 1];
        snprintf(vrf_name, sizeof vrf_name, "ovnvrf%"PRIi64,
                 ad->key);

        if (ad->maintain_vrf) {
            int error = re_nl_create_vrf(vrf_name, ad->key);
            if (error && error != EEXIST) {
                VLOG_WARN_RL(&rl,
                             "Unable to create VRF %s for datapath "
                             "%ld: %s.",
                             vrf_name, ad->key,
                             ovs_strerror(error));
                goto out;
            }
            sset_add(&_maintained_vrfs, vrf_name);
        }

        maintained_route_table_add(ad->key, ad->use_netns);

        re_nl_sync_routes(ad->key,
                          &ad->routes, &received_routes, ad->use_netns);

        sb_sync_learned_routes(ad->db, &received_routes,
                               &ad->bound_ports,
                               r_ctx_in->ovnsb_idl_txn,
                               r_ctx_in->sbrec_route_by_datapath);

        struct route_table_watch_request *wr = xzalloc(sizeof(*wr));
        wr->table_id = ad->key;
        wr->is_netns = ad->use_netns;
        hmap_insert(&r_ctx_out->route_table_watches, &wr->node,
                    route_table_notify_hash_watch(wr->table_id, wr->is_netns));

out:
        received_routes_destroy(&received_routes);
    }

    /* Remove routes in tables previousl maintained by us. */
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_SAFE(mrt, node, &old_maintained_route_table) {
        if (!maintained_route_table_contains(mrt->table_id, mrt->is_netns)) {
            re_nl_cleanup_routes(mrt->table_id, mrt->is_netns);
        }
        hmap_remove(&old_maintained_route_table, &mrt->node);
        free(mrt);
    }
    hmap_destroy(&old_maintained_route_table);

    /* Remove VRFs previously maintained by us not found in the above loop. */
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &old_maintained_vrfs) {
        if (!sset_find(&_maintained_vrfs, vrf_name)) {
            re_nl_delete_vrf(vrf_name);
        }
        sset_delete(&old_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }
    sset_destroy(&old_maintained_vrfs);
}

static void
route_exchange_cleanup__(bool cleanup)
{
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_SAFE(mrt, node, &_maintained_route_tables) {
        if (cleanup) {
            re_nl_cleanup_routes(mrt->table_id, mrt->is_netns);
        } else {
            hmap_remove(&_maintained_route_tables, &mrt->node);
            free(mrt);
        }
    }

    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &_maintained_vrfs) {
        if (cleanup) {
            re_nl_delete_vrf(vrf_name);
        } else {
            sset_delete(&_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
        }
    }

    if (!cleanup) {
        sset_destroy(&_maintained_vrfs);
        hmap_destroy(&_maintained_route_tables);
    }
}

void
route_exchange_cleanup(void)
{
    route_exchange_cleanup__(true);
}

void
route_exchange_destroy(void)
{
    route_exchange_cleanup__(false);
}
