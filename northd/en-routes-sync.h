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

bool routes_sync_northd_change_handler(struct engine_node *node,
                                       void *data OVS_UNUSED);
void *en_routes_sync_init(struct engine_node *, struct engine_arg *);
void en_routes_sync_cleanup(void *data);
void en_routes_sync_run(struct engine_node *, void *data);


#endif /* EN_ROUTES_SYNC_H */
