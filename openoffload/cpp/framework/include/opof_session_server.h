/*
 *  Copyright (C) 2020 Palo Alto Networks Intellectual Property. All rights reserved.
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

#ifndef __OPOF_SESSION_SERVER_H
#define __OPOF_SESSION_SERVER_H

/**
* \defgroup serverlibrary  C++ Server Interfaces
*
* \brief Internal C++ Server Interfaces called by the external C Interfaces
*
*/
extern "C" {
#include "opof.h"
}
#include "opof_grpc.h"


class SessionTableImpl final : public SessionTable::Service {
public:  
    Status getServiceVersion(ServerContext* context, const versionRequest* request, versionResponse* response) override;
    Status reset(ServerContext* context, const resetRequest *request, sessionResponse *response) override;
    Status addSession(ServerContext* context, ServerReader<sessionRequest>* reader, addSessionResponse* response) override;
    Status getSession(ServerContext* context, const sessionId* sid, sessionResponse* response) override;
    Status deleteSession(ServerContext* context, const sessionId* sid, sessionResponse* response) override;
    Status getAllSessions(ServerContext* context, const sessionRequestArgs* request, sessionResponses *responseArray) override;
    Status getClosedSessions(ServerContext* context,  const sessionRequestArgs* response,ServerWriter<sessionResponse>* writer) override;
    Status addVlanFlow(ServerContext* context, const vlanFlowDef* request, sessionResponse* response) override;
    Status removeVlanFlow(ServerContext* context, const vlanFlowDef* request, sessionResponse* response) override;
    Status getVlanFlows(ServerContext* context, const vlanFlowListRequest* request, vlanFlowList* response) override;
    Status clearVlanFlows(ServerContext* context, const vlanFlowListRequest* request, sessionResponse* response) override;
    Status setNextHop(ServerContext* context, const nextHopParameters *nextHop, nextHopResponse *response) override;
    Status destroyNextHop(ServerContext* context, const nextHopParameters *nextHop, nextHopResponse *response) override;
    Status clearNextHops(ServerContext* context, const nextHopParameters* ignored, nextHopResponse* response);

};


#endif