// Copyright (C) 2020 Palo Alto Networks Intellectual Property. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#ifndef OPOF_SERVERLIB_H
#define OPOF_SERVERLIB_H

/** \defgroup servercinterface C Server Interface
*
*
* \brief External C Server Interfaces called user applications
*/
#include "opof.h"
#include "opof_error.h"

#ifdef __cplusplus
extern "C" {
#endif

int opof_get_version(
    char * vendor,    size_t vendorMaxLength,
    char * name,      size_t nameMaxLength,
    char * version,   size_t versionMaxLength,
    char * copyright, size_t copyrightMaxLength);
int opof_reset_server(void);
int opof_add_session_server(sessionRequest_t *parameters, addSessionResponse_t *response);
int opof_get_session_server(unsigned long sessionId, sessionResponse_t *response);
int opof_del_session_server(unsigned long sessionId, sessionResponse_t *response);
int opof_get_closed_sessions_server(statisticsRequestArgs_t *request, sessionResponse_t responses[]);
int opof_get_all_sessions_server(int pageSize, uint64_t *startSession,int pageCount, sessionResponse_t **responses);
int opof_add_vlan_flow_server(uint16_t vlan_id, uint16_t vf_index);
int opof_remove_vlan_flow_server(uint16_t vlan_id);
size_t opof_get_vlan_flow_count_server();
int opof_get_vlan_flows_server(uint16_t *vlan_ids, uint16_t *vf_indices, size_t vlanFlowMaxCount, size_t *vlanFlowActualCount);
int opof_clear_vlan_flows_server();
int opof_set_next_hop_server(struct nextHopParameters_t *nextHop_c);
int opof_destroy_next_hop_server(uint32_t nextHopId);
int opof_clear_next_hops_server();

#ifdef __cplusplus
}
#endif

#endif
