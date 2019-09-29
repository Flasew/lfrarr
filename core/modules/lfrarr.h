// Copyright (c) 2017, Joshua Stone.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_MODULES_LFRARR_H_
#define BESS_MODULES_LFRARR_H_

#include <cstdlib>

#include <rte_hash_crc.h>

#include "../kmod/llring.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../pktbatch.h"
#include "../utils/cuckoo_map.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

#include <queue>
#include <vector>

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;

using bess::utils::Ipv4Prefix;
using bess::utils::CuckooMap;

// comment to be completed
class LFRArr final : public Module {
 public:
  // the default max number of flows allowed + 1
  static const int kDefaultNumFlows = 4096;
  static const int kFlowQueueSize = 4096;  // initial queue size for a flow
  static const int kQueueGrowthFactor =
      2;  // the scale at which a flow's queue grows
  static const int kFlowQueueMax =
      8192;                     // the max flow queue size if non-specified
  static const int kOOBufMax = 4096;
  static const int kPacketOverhead =
      24;  // additional bytes associated with packets
  static const int kTtl = 300;  // time to live for flow entries


  // 5 tuple id to identify a flow from a packet header information.
  struct FlowId {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t src_port;
    uint32_t dst_port;
    uint8_t protocol;
  };

  // compare two packets
  struct PacketGreaterThan {
    bool operator()(const bess::Packet* p1, const bess::Packet* p2) const {
      return (int32_t)(LFRArr::GetSeq(p1)-LFRArr::GetSeq(p2)) > 0;
    }
  };

  // stores the metrics of the flow, a timer and the queue to store the packets
  // in.
  struct Flow {
    // enum FlowState
    // {
    //   ACTIVE_MERGE;
    //   LOSS_RECOVERY;
    //   // DEAD_FLOW;
    // };
    // FlowState state;
    double timer;               // to determine if TTL should be used
    double pq_timer;
    FlowId id;                  // allows the flow to remove itself from the map
    uint32_t expected_next;
    uint32_t lost_seq;
    struct llring *queue;       // queue to store current packets for flow
    bess::Packet *next_packet;  // buffer to store next packet from the queue.
    std::priority_queue<bess::Packet *, 
      std::vector<bess::Packet *>, 
      PacketGreaterThan> pq; // packet pq

    Flow() 
        : timer(0), id(), expected_next(0), next_packet(nullptr){};
    Flow(FlowId new_id)
        : timer(0), id(new_id), expected_next(0), next_packet(nullptr){};
    Flow(FlowId new_id, uint32_t s)
        : timer(0), id(new_id), expected_next(s), next_packet(nullptr){};

    ~Flow() {
      if (queue) {
        bess::Packet *pkt;
        while (llring_sc_dequeue(queue, reinterpret_cast<void **>(&pkt)) == 0) {
          bess::Packet::Free(pkt);
        }

        std::free(queue);
      }

      if (next_packet) {
        bess::Packet::Free(next_packet);
      }

      bess::Packet * p;
      while (!pq.empty()) {
        p = pq.top();
        pq.pop();
        bess::Packet::Free(p);
      }
    }
  };

  // hashes a FlowId
  struct Hash {
    // a similar method to boost's hash_combine in order to combine hashes
    inline void combine(std::size_t &hash, const unsigned int &val) const {
      std::hash<unsigned int> hasher;
      hash ^= hasher(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    }
    bess::utils::HashResult operator()(const FlowId &id) const {
      std::size_t hash = 0;
      combine(hash, id.src_ip);
      combine(hash, id.dst_ip);
      combine(hash, id.src_port);
      combine(hash, id.dst_port);
      combine(hash, (uint32_t)id.protocol);
      return hash;
    }
  };

  // to compare two FlowId for equality in a hash table
  struct EqualTo {
    bool operator()(const FlowId &id1, const FlowId &id2) const {
      bool ips = (id1.src_ip == id2.src_ip) && (id1.dst_ip == id2.dst_ip);
      bool ports =
          (id1.src_port == id2.src_port) && (id1.dst_port == id2.dst_port);
      return (ips && ports) && (id1.protocol == id2.protocol);
    }
  };

  LFRArr();   // constructor
  ~LFRArr();  // deconstructor

  static const Commands cmds;

  CommandResponse Init(const bess::pb::LFRArrArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch,
                             void *arg) override;

  CommandResponse CommandMaxFlowQueueSize(
      const bess::pb::LFRArrMaxFlowQueueSizeArg &arg);
  CommandResponse CommandOOQueueSize(
      const bess::pb::LFRArrOOQueueSizeArg &arg);
  CommandResponse CommandFlowTimeout(
      const bess::pb::LFRArrFlowTimeoutArg &arg);
  CommandResponse CommandMaxFlowNum(
      const bess::pb::LFRArrMaxFlowNumArg &arg);

 private:
  static uint32_t GetSeq(const bess::Packet* const pkt);

  //  Sets the maximum size that any Flows queue can get before the module will
  //  start dropping the flows packets. Takes the maximum size for any Flows
  //  queue.
  //  Returns 0 on success and error value otherwise.
  CommandResponse SetMaxFlowQueueSize(uint32_t queue_size);
  CommandResponse SetOOQueueSize(uint32_t queue_size);
  CommandResponse SetFlowTimeout(double tout);
  CommandResponse SetMaxFlowNum(uint32_t flow_n);
  CommandResponse SetOOTimeout(double tout);

  //  Creates a new larger llring queue of the specifed size and moves over all
  //  of the entries from the old queue and frees the old_queue. Takes a pointer
  //  to the
  //  location of the  current queue, the new size of the queue and integer
  //  pointer
  //  to set on error. If the integer pointer is set than the return value will
  //  be
  //  a
  //  nullptr. Returns a pointer to the new llring otherwise.
  llring *ResizeQueue(llring *old_queue, uint32_t new_size, int *err);

  //  Puts the packet into the llring queue within the flow. Takes the flow to
  //  enqueue the packet into, the packet to enqueue into the flow's queue
  //  and integer pointer to be set on error.
  void Enqueue(Flow *f, bess::Packet *pkt, int *err);

  //  Takes a Packet to get a flow id for. Returns the 5 element identifier for
  //  the flow that the packet belongs to
  FlowId GetId(bess::Packet *pkt);

  //  Creates a new flow and adds it to the round robin queue. Takes the first
  //  pkt
  //  to be enqueued in the new flow, the id of the new flow to be created and
  //  integer pointer to set on error.
  void AddNewFlow(bess::Packet *pkt, FlowId id, int *err);

  //  Removes the flow from the hash table and frees all the packets within its
  //  queue. Takes the pointer to the flow to remove
  void RemoveFlow(Flow *f);

  //  Obtain the next batch of packets from the next flows in round robin.
  //  Takes a PacketBatch to insert the packets into and integer pointer
  //  to set on error. Returns total bytes added to batch.
  uint32_t GetNextBatch(bess::PacketBatch *batch, int *err);

  //  gets the next set of packets from flow given allocated bytes
  //  Takes the PacketBatch to put the packets into and the flow to get the
  //  packets
  //  from and integer pointer to set on error. Returns the total bytes put in
  //  batch
  uint32_t GetNextPackets(bess::PacketBatch *batch, Flow *f, int *err);

  //  gets the next flow from the queue of flows. Returns nullptr if the next
  //  flow is empty or if the flow is deleted. If there is a an error returns
  //  an error and sets the integer pointer to error value.
  Flow *GetNextFlow(int *err);

  //  allocates llring queue space and adds the queue to the specified flow with
  //  size indicated by slots. Takes the Flow to add the queue, the number
  //  of slots for the queue to have and the integer pointer to set on error.
  //  Returns a llring queue.
  llring *AddQueue(uint32_t slots, int *err);

  const Ipv4 * GetIpv4Header(const bess::Packet * const pkt) const;

  const Tcp * GetTCPHeader(const bess::Packet * const pkt) const;

  void RunLFRA(Flow * f, bess::Packet * pkt, int * err);

  void UpdateExpected(Flow * f, bess::Packet * p);

  // max size of a flow's queue before the module will start dropping
  // the flow's packets
  uint32_t max_queue_size_;

  // max number of flow's that the module will handle.
  uint32_t max_number_flows_;

  uint32_t max_ofo_buffsize_;

  double flow_timeout_;
  double oo_timeout_;

  // state map used to reunite packets with their flow
  CuckooMap<FlowId, Flow *, Hash, EqualTo> flows_;
  llring *flow_ring_;   // llring used for round robin.
  Flow *current_flow_;  // store current flow between batch rounds.
};
#endif  // BESS_MODULES_LFRARR_H_

