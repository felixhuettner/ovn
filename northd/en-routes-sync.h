/*
 * Copyright (c) 2023, Red Hat, Inc.
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
#ifndef EN_ROUTES_SYNC_H
#define EN_ROUTES_SYNC_H 1

#include "lib/inc-proc-eng.h"
#include "lib/uuidset.h"
#include "openvswitch/hmap.h"

struct routes_sync_tracked_data {
  /* Contains the uuids of all NB Logical Routers where we used a
   * lr_stateful_record during computation. */
  struct uuidset nb_lr_stateful;
};

struct routes_sync_data {
    struct hmap parsed_routes;

    /* Node's tracked data. */
    struct routes_sync_tracked_data trk_data;
};

bool routes_sync_northd_change_handler(struct engine_node *node,
                                       void *data);
bool routes_sync_lr_stateful_change_handler(struct engine_node *node,
                                            void *data);
void *en_routes_sync_init(struct engine_node *, struct engine_arg *);
void en_routes_sync_cleanup(void *data);
void en_routes_sync_clear_tracked_data(void *data);
void en_routes_sync_run(struct engine_node *, void *data);


#endif /* EN_ROUTES_SYNC_H */
