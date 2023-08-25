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

/**
*
* \class SessionTableClient
*
* \defgroup clientlibrary  C++ Client Interfaces
*
* \brief Internal C++ Client Interfaces called by the external C Interfaces
*
*/

#ifndef __OPOF_SESSION_CLIENT_H
#define __OPOF_SESSION_CLIENT_H


extern "C" {
#include "opof.h"
}
#include "opof_grpc.h"

class SessionTableClient {
public: 
	/** \brief Constructor
	 *
	 */
    SessionTableClient(std::shared_ptr<Channel> channel)
    : stub_(SessionTable::NewStub(channel)) {};

    /** \brief Retrieves version information from the offload service.
    * \details On success, the returned string objects are valid for
    *          the lifetime of the client object.
    * \param vendor of the offload service
    * \param name of the offload service
    * \param version of the offload service
    * \param copyright of the offload service
    */
    int getServiceVersion(
        const char **vendor,
        const char **name,
        const char **version,
        const char **copyright);

     /** \brief adds a session to the server
      *
      * \param size
      * \param s
      * \param resp
      * \return int error code
      * 
      * This sends the session information to the server to offload.
      */
    int addSessionClient(int size, sessionRequest_t **s, addSessionResponse_t *resp);
    int getSessionClient(int session, sessionResponse_t *resp);
    int deleteSessionClient(int session, sessionResponse_t *resp);
    int getAllSessions(int pageSize, uint64_t *start_session, uint64_t *sessions, sessionResponse_t responses[],unsigned long *sessionCount);
    int getClosedSessions(statisticsRequestArgs_t *args, sessionResponse_t responses[], unsigned long *sessionCount);
    int addVlanFlow(uint16_t vlan_id, uint16_t vf_index);
    size_t getVlanFlowCount();
    int getVlanFlows(uint16_t *vlan_ids, uint16_t *vf_indices, size_t vlanFlowMaxCount, size_t * vlanFlowActualCount);
    int removeVlanFlow(uint16_t vlan_id);
    int clearVlanFlows();
    int setNextHop(const struct nextHopParameters_t *nextHop);
    int destroyNextHop(uint32_t nextHopID);
    int clearNextHops();
private:
    std::unique_ptr<SessionTable::Stub> stub_;
    std::unique_ptr<versionResponse> versionInfo_;
};


#endif
