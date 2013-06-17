/*
 * mobileap-agent
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MOBILEAP_NETWORK_H__
#define __MOBILEAP_NETWORK_H__

#include <glib.h>

gboolean _get_network_interface_name(char **if_name);
gboolean _is_trying_network_operation(void);
gboolean _set_masquerade(void);
gboolean _unset_masquerade(void);
gboolean _open_network(void);
gboolean _close_network(void);
gboolean _init_network(void *user_data);
gboolean _deinit_network(void);

#endif /* __MOBILEAP_NETWORK_H__ */
