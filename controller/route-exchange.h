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

#ifndef ROUTE_EXCHANGE_H
#define ROUTE_EXCHANGE_H 1

#include <stdbool.h>
#include "openvswitch/hmap.h"

struct route_exchange_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_index *sbrec_route_by_datapath;
    /* Contains struct advertise_datapath_entry */
    struct hmap *announce_routes;
};

struct route_exchange_ctx_out {
    /* contains route_table_watch */
    struct hmap route_table_watches;
};

void route_exchange_run(struct route_exchange_ctx_in *,
                        struct route_exchange_ctx_out *);
void route_exchange_cleanup(void);
void route_exchange_destroy(void);

#endif /* ROUTE_EXCHANGE_H */