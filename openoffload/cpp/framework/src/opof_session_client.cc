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


extern "C" {
#include "opof.h"
#ifdef DEBUG
#include "opof_test_util.h"
#endif
  //
  // Set default deadline on API calls to 100 milli seconds
  //
  unsigned int g_deadline = 100;
  /**  \ingroup clientcinterface
  * \brief gets the deadline value in milli-seconds
  *
  * \param void
  * \return value of global value deadline
  *
  */
  unsigned int opof_get_deadline(void){
    return g_deadline;
  }
 /**  \ingroup clientcinterface
  * \brief sets the deadline value in milli-seconds
  *
  * \param int
  * \return value of global value deadline
  *
  */
  unsigned int opof_set_deadline(int deadline){
    g_deadline = deadline;
    return g_deadline;
  }
} // extern C

#include "opof_util.h"
#include "opof_grpc.h"
#include "opof_session_client.h"

/**  \ingroup clientlibrary
* \brief Retrieves version information from the offload service.
* \details On success, the returned string objects are valid for
*          the lifetime of the client object.
* \param vendor of the offload service
* \param name of the offload service
* \param version of the offload service
* \param copyright of the offload service
*/
int SessionTableClient::getServiceVersion(
  const char **vendor,
  const char **name,
  const char **version,
  const char **copyright)
{
  if (!versionInfo_) {
    ClientContext context;
    versionRequest tmpVersionRequest;
    versionResponse tmpVersionInfo;
    Status status = stub_->getServiceVersion(&context, tmpVersionRequest, &tmpVersionInfo);
    if (status.error_code() != Status::OK.error_code()) {
      return static_cast<int>(status.error_code());
    }
    versionInfo_.reset(new versionResponse(tmpVersionInfo));
  }

  // The versionInfo_ object owns the memory for the strings.
  // The strings returned by this function are valid for the
  // lifetime of this client.
  *vendor    = versionInfo_->vendor().c_str();
  *name      = versionInfo_->name().c_str();
  *version   = versionInfo_->version().c_str();
  *copyright = versionInfo_->copyright().c_str();

  return static_cast<int>(Status::OK.error_code());
}


/**  \ingroup clientlibrary
* \brief
*
* \param size
* \param sessionRequest_t
* \param addSeesionResponse_t
*
*/
int SessionTableClient::addSessionClient(int size, sessionRequest_t **s, addSessionResponse_t *resp){

  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);
  #ifdef DEBUG
  std::cout << "Deadline set for add session: " << opof_get_deadline() << " milli seconds" << endl;
  #endif
  addSessionResponse response;
  std::unique_ptr<ClientWriter <sessionRequest> > writer(
          stub_->addSession(&context, &response));

  for (int i=0; i< size; i++){
    sessionRequest_t *request_c = s[i];
  #ifdef DEBUG
    display_session_request(request_c, "addSessionClient");
  #endif
    sessionRequest request;
    convertSessionRequest2cpp(request_c, &request);
    writer->Write(request);
  }
  writer->WritesDone();
  Status status = writer->Finish();
  convertAddSessionResponse2c(resp,&response);
  //std::cout << "Status code: " <<  static_cast<int>(status.error_code()) << endl;
  return static_cast<int>(status.error_code());
}
/**  \ingroup clientlibrary
* \brief getSessionClient
*
* \param size
* \param sessionRequest_t
* \param addSeesionResponse_t
*
*/
int SessionTableClient::getSessionClient(int sessionid,sessionResponse_t *resp){

  sessionId sid;
  sessionResponse response;
  sid.set_sessionid(sessionid);
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);
  #ifdef DEBUG
  std::cout << "Deadline set for get session: " << opof_get_deadline() << " milli seconds" << endl;
  #endif
  Status status = stub_->getSession(&context, sid, &response);
  convertSessionResponse2c(&response, resp);
  return static_cast<int>(status.error_code());
}

/**  \ingroup clientlibrary
* \brief deleteSessionClient
*
* \param size
* \param sessionRequest_t
* \param addSeesionResponse_t
*
*/
int SessionTableClient::deleteSessionClient(int sessionid,sessionResponse_t *resp){

  sessionId sid;
  sessionResponse response;
  sid.set_sessionid(sessionid);
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);
  #ifdef DEBUG
  std::cout << "Deadline set for delete session: " << opof_get_deadline() << " milli seconds" << endl;
  #endif
  Status status = stub_->deleteSession(&context, sid, &response);

  convertSessionResponse2c(&response, resp);
  #ifdef DEBUG
    display_session_response(resp, "delSessionClient");
  #endif

  return static_cast<int>(status.error_code());
}
/**  \ingroup clientlibrary
* \brief getClosedSessions
*
* \param size
* \param sessionRequest_t
* \param addSeesionResponse_t
*
*/
int SessionTableClient::getClosedSessions(statisticsRequestArgs_t *args, sessionResponse_t responses[], unsigned long *sessionCount){
  sessionResponse response;
  sessionRequestArgs request;
  ClientContext context;
  request.set_pagesize(args->pageSize);
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);
  #ifdef DEBUG
  std::cout << "Deadline set for get closed sessions: " << opof_get_deadline() << " milli seconds" << endl;
  #endif
  *sessionCount = 0;
  std::unique_ptr<ClientReader <sessionResponse> > reader(
        stub_->getClosedSessions(&context, request));
  while (reader->Read(&response)) {
    convertSessionResponse2c(&response, &responses[*sessionCount]);
    (*sessionCount)++;
  }
  Status status = reader->Finish();
  return static_cast<int>(status.error_code());
}
/**  \ingroup clientlibrary
* \brief getAllSessions
*
* \param size
* \param sessionRequest_t
* \param addSeesionResponse_t
*
*/
int  SessionTableClient::getAllSessions(int pageSize, uint64_t *session_start_id, uint64_t *session_count, sessionResponse_t responses[], unsigned long *sessionCount){
  
  Status status;
  sessionResponses response;
  sessionRequestArgs request;
  ClientContext context;
 
  int array_size;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);
  #ifdef DEBUG
  std::cout << "Deadline set for get all sessions: " << opof_get_deadline() << " milli seconds" << endl;
  #endif
  request.set_pagesize(pageSize);
  request.set_startsession(*session_start_id);
  
  status = stub_->getAllSessions(&context, request, &response);
  array_size = response.sessioninfo_size();
  *session_start_id = response.nextkey();
 

  for (int i = 0; i < array_size; i++ ){
    convertSessionResponse2c(response.mutable_sessioninfo(i), &responses[i]);
  }

  *session_count = array_size;
  
  return static_cast<int>(status.error_code());
}

int SessionTableClient::addVlanFlow(uint16_t vlan_id, uint16_t vf_index)
{
  Status status;
  sessionResponse response;
  vlanFlowDef request;
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  request.set_vlanid(vlan_id);
  request.set_internallif(vf_index);
  
  status = stub_->addVlanFlow(&context, request, &response);
  
  return static_cast<int>(status.error_code());
}

int SessionTableClient::removeVlanFlow(uint16_t vlan_id)
{
  Status status;
  sessionResponse response;
  vlanFlowDef request;
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  request.set_vlanid(vlan_id);
  
  status = stub_->removeVlanFlow(&context, request, &response);
  
  return static_cast<int>(status.error_code());
}

size_t SessionTableClient::getVlanFlowCount()
{
  Status status;
  vlanFlowList response;
  vlanFlowListRequest request;
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  status = stub_->getVlanFlows(&context, request, &response);

  if (status.error_code() == Status::OK.error_code())
  {
    return response.flowdefs_size();
  }  
  return -1;
}

int SessionTableClient::getVlanFlows(
  uint16_t *vlan_ids, 
  uint16_t *vf_indices, 
  size_t vlanFlowMaxCount,
  size_t * vlanFlowActualCount)
{
  Status status;
  vlanFlowList response;
  vlanFlowListRequest request;
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  if (vlanFlowActualCount)
    *vlanFlowActualCount = 0;

  status = stub_->getVlanFlows(&context, request, &response);

  if (status.error_code() == Status::OK.error_code() &&
    response.flowdefs_size() <= (int)vlanFlowMaxCount)
  {
    for (int i=0; i<response.flowdefs_size(); i++) {
      vlan_ids[i] = response.flowdefs(i).vlanid();
      vf_indices[i] = response.flowdefs(i).internallif();
    }

    if (vlanFlowActualCount)
      *vlanFlowActualCount = response.flowdefs_size();
  }

  return static_cast<int>(status.error_code());
}

int SessionTableClient::clearVlanFlows()
{
  Status status;
  sessionResponse response;
  vlanFlowListRequest request;
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  status = stub_->clearVlanFlows(&context, request, &response);
  return static_cast<int>(status.error_code());
}

int SessionTableClient::setNextHop(
  const struct nextHopParameters_t *nextHop_c)
{
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  nextHopParameters request;
  convertNextHop2cpp(nextHop_c, &request);

  nextHopResponse response;
  Status status = stub_->setNextHop(&context, request, &response);

  return static_cast<int>(status.error_code());
}

int SessionTableClient::destroyNextHop(
  uint32_t nextHopID)
{
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  nextHopParameters request;
  request.set_nexthopid(nextHopID);

  nextHopResponse response;
  Status status = stub_->destroyNextHop(&context, request, &response);
    
  return static_cast<int>(status.error_code());
}

int SessionTableClient::clearNextHops()
{
  ClientContext context;
  std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(opof_get_deadline());
  context.set_deadline(deadline);

  nextHopParameters request;
  nextHopResponse response;
  Status status = stub_->clearNextHops(&context, request, &response);
  
  return static_cast<int>(status.error_code());
}
