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

#include "lfrarr.h"

#include <cmath>
#include <fstream>
#include <iostream>
#include <string>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

#define _MY_DEBUG_ 

static uint32_t RoundToPowerTwo(uint32_t v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  return v;
}

bool before(uint32_t seq1, uint32_t seq2)
{
  return (int32_t)(seq1-seq2) < 0;
}
#define after(seq2, seq1)   before(seq1, seq2)

const Commands LFRArr::cmds = {
    {"set_max_flow_queue_size", "LFRArrMaxFlowQueueSizeArg",
     MODULE_CMD_FUNC(&LFRArr::CommandMaxFlowQueueSize), Command::THREAD_UNSAFE},
    {"set_oo_queue_size", "LFRArrOOQueueSizeArg",
     MODULE_CMD_FUNC(&LFRArr::CommandOOQueueSize), Command::THREAD_UNSAFE},
    {"set_flow_timeout", "LFRArrFlowTimeoutArg",
     MODULE_CMD_FUNC(&LFRArr::CommandFlowTimeout), Command::THREAD_UNSAFE},
    {"set_max_flow_number", "LFRArrMaxFlowNumArg",
     MODULE_CMD_FUNC(&LFRArr::CommandMaxFlowNum), Command::THREAD_UNSAFE}};

LFRArr::LFRArr() : 
      max_queue_size_(kFlowQueueMax),
      max_number_flows_(kDefaultNumFlows),
      max_ofo_buffsize_(kOOBufMax),
      flow_timeout_(kTtl),
      flow_ring_(nullptr),
      current_flow_(nullptr) {
  is_task_ = true;
  max_allowed_workers_ = Worker::kMaxWorkers;
}

LFRArr::~LFRArr() {
  for (auto it = flows_.begin(); it != flows_.end();) {
    RemoveFlow(it->second);
    it++;
  }
  std::free(flow_ring_);
}

CommandResponse LFRArr::Init(const bess::pb::LFRArrArg &arg) {
  CommandResponse err;
  task_id_t tid;

  if (arg.num_flows() != 0) {
    max_number_flows_ = RoundToPowerTwo(arg.num_flows() + 1);
  }

  if (arg.max_flow_queue_size() != 0) {
    err = SetMaxFlowQueueSize(arg.max_flow_queue_size());
    if (err.error().code() != 0) {
      return err;
    }
  }

  if (arg.num_oo_pkt() != 0) {
    err = SetOOQueueSize(arg.num_oo_pkt());
    if (err.error().code() != 0) {
      return err;
    }
  }

  // oof
  if (arg.flow_ttl() != 0) {
    err = SetFlowTimeout(arg.flow_ttl());
    if (err.error().code() != 0) {
      return err;
    }
  }

  // register task
  tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "task creation failed");
  }

  int err_num = 0;
  flow_ring_ = AddQueue(max_number_flows_, &err_num);
  if (err_num != 0) {
    return CommandFailure(-err_num);
  }

  return CommandSuccess();
}


// message LFRArrMaxFlowQueueSizeArg {
//   uint32 max_queue_size = 1;  /// the max size that any Flows queue can get
// }

// message LFRArrOOQueueSizeArg {
//   uint32 oo_queue_size = 1; 
// }

// message LFRArrFlowTimeoutArg {
//   double flow_timeout = 1000;  /// the max size that any Flows queue can get
// }

// message LFRArrMaxFlowNumArg {
//   uint32 max_flow_num = 1;  /// the max size that any Flows queue can get
// }

// {"set_max_flow_queue_size", "LFRArrMaxFlowQueueSizeArg",
//  MODULE_CMD_FUNC(&LFRArr::CommandMaxFlowQueueSize), Command::THREAD_UNSAFE},
// {"set_oo_queue_size", "LFRArrOOQueueSizeArg",
//  MODULE_CMD_FUNC(&LFRArr::CommandOOQueueSize), Command::THREAD_UNSAFE},
// {"set_flow_timeout", "LFRArrFlowTimeoutArg",
//  MODULE_CMD_FUNC(&LFRArr::CommandFlowTimeout), Command::THREAD_UNSAFE},
// {"set_max_flow_number", "LFRArrMaxFlowNumArg",
//  MODULE_CMD_FUNC(&LFRArr::CommandMaxFlowNum), Command::THREAD_UNSAFE}};

CommandResponse LFRArr::CommandMaxFlowQueueSize(
    const bess::pb::LFRArrMaxFlowQueueSizeArg &arg) {
  return SetMaxFlowQueueSize(arg.max_queue_size());
}

CommandResponse LFRArr::CommandOOQueueSize(
    const bess::pb::LFRArrOOQueueSizeArg &arg) {
  return SetOOQueueSize(arg.oo_queue_size());
}

CommandResponse LFRArr::CommandFlowTimeout(
    const bess::pb::LFRArrFlowTimeoutArg &arg) {
  return SetFlowTimeout(arg.flow_timeout());
}

CommandResponse LFRArr::CommandMaxFlowNum(
    const bess::pb::LFRArrMaxFlowNumArg &arg) {
  return SetMaxFlowNum(arg.max_flow_num());
}


void LFRArr::ProcessBatch(Context *, bess::PacketBatch *batch) {
  int err = 0;

  // insert packets in the batch into their corresponding flows
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {

#ifdef _MY_DEBUG_
    std::cerr << "[DEBUG] New packet entered LFRA" << std::endl;
#endif

    bess::Packet *pkt = batch->pkts()[i];

    // TODO(joshua): Add support for fragmented packets.
    FlowId id = GetId(pkt);
    auto it = flows_.Find(id);

    // if the Flow doesn't exist create one
    // and add the packet to the new Flow
    if (it == nullptr) {
      if (llring_full(flow_ring_)) {
        bess::Packet::Free(pkt);

#ifdef _MY_DEBUG_
        std::cerr << "[DEBUG] Flow buffer full, packed discarded" << std::endl;
#endif

      } else {
        AddNewFlow(pkt, id, &err);

#ifdef _MY_DEBUG_
        std::cerr << "[DEBUG] Adding new flow" << std::endl;
#endif

        assert(err == 0);
      }
    } else {
      RunLFRA(it->second, pkt, &err);

#ifdef _MY_DEBUG_
      std::cerr << "[DEBUG] Running LFRA" << std::endl;
#endif

      assert(err == 0);
    }
  }
}

struct task_result LFRArr::RunTask(Context *ctx, bess::PacketBatch *batch,
                                void *) {
  if (children_overload_ > 0) {
    return {
        .block = true, .packets = 0, .bits = 0,
    };
  }

  int err = 0;
  batch->clear();
  uint32_t total_bytes = 0;
  if (flow_ring_ != NULL) {
    total_bytes = GetNextBatch(batch, &err);
  }
  assert(err >= 0);  // TODO(joshua) do proper error checking

  if (total_bytes > 0) {
#ifdef _MY_DEBUG_
    std::cerr << "[DEBUG] RunTask - Handing to next module" << std::endl;
#endif
    RunNextModule(ctx, batch);
  }

  // the number of bits inserted into the packet batch
  uint32_t cnt = batch->cnt();
  uint64_t bits_retrieved = (total_bytes + cnt * kPacketOverhead) * 8;
  return {.block = (cnt == 0), .packets = cnt, .bits = bits_retrieved};
}

uint32_t LFRArr::GetNextBatch(bess::PacketBatch *batch, int *err) {

  //std::cerr << "[DEBUG] Entering GetNextBatch" << std::endl;

  Flow *f;
  uint32_t total_bytes = 0;
  uint32_t count = llring_count(flow_ring_);
  if (current_flow_) {
    count++;
  }
  int batch_size = batch->cnt();

  // iterate through flows in round robin fashion until batch is full
  while (!batch->full()) {
    // checks to see if there has been no update after a full round
    // ensures that if every flow is empty or if there are no flows
    // that will terminate with a non-full batch.
    if (count == 0) {
      if (batch_size == batch->cnt()) {
        break;
      } else {
        count = llring_count(flow_ring_);
        batch_size = batch->cnt();
      }
    }
    count--;

    f = GetNextFlow(err);
    if (*err != 0) {
      return total_bytes;
    } else if (f == nullptr) {
      continue;
    }

    uint32_t bytes = GetNextPackets(batch, f, err);
    total_bytes += bytes;
    if (*err != 0) {
      return total_bytes;
    }

    // if (llring_empty(f->queue) && !f->next_packet) {
    //   f->deficit = 0;
    // }

    // if the flow doesn't have any more packets to give, reenqueue it
    if (!f->next_packet) {
      *err = llring_enqueue(flow_ring_, f);
      if (*err != 0) {
        return total_bytes;
      }
    } else {
      // knowing that the while statement will exit, keep the flow that still
      // has packets at the front
      current_flow_ = f;
    }
  }

  //std::cerr << "[DEBUG] Exiting GetNextBatch, total_bytes=" << total_bytes << std::endl;

  return total_bytes;
}

LFRArr::Flow *LFRArr::GetNextFlow(int *err) {

  // std::cerr << "[DEBUG] Entering GetNextFlow" << std::endl;

  Flow *f;
  bess::Packet * p = nullptr;
  double now = get_epoch_time();

  if (!current_flow_) {
    *err = llring_dequeue(flow_ring_, reinterpret_cast<void **>(&f));
    if (*err < 0) {
#ifdef _MY_DEBUG_
      std::cerr << "[DEBUG] GetNextFlow dequeue error" << std::endl;
#endif
      return nullptr;
    }

    if (llring_empty(f->queue) && !f->next_packet) {

      //std::cerr << "[DEBUG] GetNextFlow: now=" << now 
      //  << ", f->timer=" << f->timer 
      //  << ", diff=" << (now - f->timer) << std::endl; 

      // if the flow expired, remove it
      if (now - f->timer > flow_timeout_) {

#ifdef _MY_DEBUG_
        std::cerr << "[DEBUG] GetNextFlow: Timer expired" << std::endl;
#endif
        
        if (f->pq.empty()) {
          RemoveFlow(f);
#ifdef _MY_DEBUG_
          std::cerr << "[DEBUG] GetNextFlow: Flow removed" << std::endl;
#endif
          return nullptr;
        }
        else {
          while (!f->pq.empty()) {
            p = f->pq.top();
            f->pq.pop();
            *err = llring_enqueue(f->queue, p);
          }
          *err = llring_dequeue(f->queue, reinterpret_cast<void **>(&p));
          f->next_packet = p;
#ifdef _MY_DEBUG_
          std::cerr << "[DEBUG] GetNextFlow: PQ evicted" << std::endl;
#endif
        }
      } 

      else {
        *err = llring_enqueue(flow_ring_, f);
        // if (*err < 0) {
          return nullptr;
        // }
      }
      
    }

    // f->deficit += quantum_;
  } else {
    f = current_flow_;
    current_flow_ = nullptr;
  }

#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] Exiting GetNextFlow, flow info: " 
    << f->id.src_ip << ":" << f->id.src_port << " -> " 
    << f->id.dst_ip << ":" << f->id.dst_port << std::endl;
#endif

  return f;
}

uint32_t LFRArr::GetNextPackets(bess::PacketBatch *batch, Flow *f, int *err) {

#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] Entering GetNextPackets" << std::endl;
#endif

  uint32_t total_bytes = 0;
  bess::Packet *pkt;

  while (!batch->full() && (!llring_empty(f->queue) || f->next_packet)) {
    // makes sure there isn't already a packet at the front
    if (!f->next_packet) {
      *err = llring_dequeue(f->queue, reinterpret_cast<void **>(&pkt));
      if (*err < 0) {
        return total_bytes;
      }
    } else {
      pkt = f->next_packet;
      f->next_packet = nullptr;
    }

    // if (pkt->total_len() > f->deficit) {
    //   f->next_packet = pkt;
    //   break;
    // }

    // f->deficit -= pkt->total_len();
    total_bytes += pkt->total_len();
    batch->add(pkt);
  }

#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] Exiting GetNextPackets, total_bytes=" << total_bytes << std::endl;
#endif

  return total_bytes;
}

LFRArr::FlowId LFRArr::GetId(bess::Packet *pkt) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;

  Ethernet *eth = pkt->head_data<Ethernet *>();
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  size_t ip_bytes = ip->header_length << 2;
  Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) +
                                     ip_bytes);  // Assumes a l-4 header
  // TODO(joshua): handle packet fragmentation
  FlowId id = {ip->src.value(), ip->dst.value(), udp->src_port.value(),
               udp->dst_port.value(), ip->protocol};
  return id;
}

void LFRArr::AddNewFlow(bess::Packet *pkt, FlowId id, int *err) {

#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] Adding Flow" << std::endl;
#endif
  // creates flow
  Flow *f = new Flow(id);

  // TODO(joshua) do proper error checking
  f->queue = AddQueue(static_cast<int>(kFlowQueueSize), err);

  if (*err != 0) {
    return;
  }

  flows_.Insert(id, f);
#ifdef _MY_DEBUG_
  const Tcp * const tcp = GetTCPHeader(pkt);

  uint32_t seq = tcp->seq_num.value();
  // Assumes we only get one SYN and the sequence number of it doesn't change
  // for any reason.  Also assumes we have no data in the SYN.
  /*
  if (tcp->flags & Tcp::Flag::kSyn) {
    f->expected_next = seq + 1;
  }
  else {
    f->expected_next = seq;
  }
  */
  std::cerr << "[DEBUG] AddFlow: flow info: " 
    << f->id.src_ip << ":" << f->id.src_port << " -> " 
    << f->id.dst_ip << ":" << f->id.dst_port << std::endl;
  std::cerr << "[DEBUG] AddFlow: init seq " << seq << ", SYN set " 
    << (tcp->flags & Tcp::Flag::kSyn) << std::endl;
#endif

  //RunLFRA(f, pkt, err);
  Enqueue(f, pkt, err);
  UpdateExpected(f,pkt);

  if (*err != 0) {
    return;
  }

  // puts flow in round robin
  *err = llring_enqueue(flow_ring_, f);
}

void LFRArr::RemoveFlow(Flow *f) {
  if (f == current_flow_) {
    current_flow_ = nullptr;
  }
  flows_.Remove(f->id);
  delete f;
}

llring *LFRArr::AddQueue(uint32_t slots, int *err) {
  int bytes = llring_bytes_with_slots(slots);
  int ret;

  llring *queue = static_cast<llring *>(aligned_alloc(alignof(llring), bytes));
  if (!queue) {
    *err = -ENOMEM;
    return nullptr;
  }

  ret = llring_init(queue, slots, 1, 1);
  if (ret) {
    std::free(queue);
    *err = -EINVAL;
    return nullptr;
  }
  return queue;
}

void LFRArr::Enqueue(Flow *f, bess::Packet *newpkt, int *err) {
  // if the queue is full. drop the packet.
  if (llring_count(f->queue) >= max_queue_size_) {
    bess::Packet::Free(newpkt);
    return;
  }

  // creates a new queue if there is not enough space for the new packet
  // in the old queue
  if (llring_full(f->queue)) {
    uint32_t slots =
        RoundToPowerTwo(llring_count(f->queue) * kQueueGrowthFactor);
    f->queue = ResizeQueue(f->queue, slots, err);
    if (*err != 0) {
      bess::Packet::Free(newpkt);
      return;
    }
  }

  *err = llring_enqueue(f->queue, reinterpret_cast<void *>(newpkt));

#ifdef _MY_DEBUG_
  const Ipv4 * const ip = GetIpv4Header(newpkt);
  const Tcp * const tcp = (Tcp *)(((const char *)ip) + (ip->header_length * 4));
  uint32_t seq = tcp->seq_num.value();
  std::cerr << "[DEBUG] Enqueued packet with seq=" << seq << std::endl;
#endif


  if (*err == 0) {
    f->timer = get_epoch_time();
  } else {
    bess::Packet::Free(newpkt);
  }
}

void LFRArr::RunLFRA(Flow * f, bess::Packet * pkt, int * err) {
  // Lowest First Resequencing Algorithm
  
  // IF (expected_num equals current_packet_num)
  // begin
  //   Release packet into output queue.
  //   Increment expected_num by 1
  //   While (expected_num in resequencing buffer)
  //     {Release that packet into output queue
  //     Increment expected_num by 1}
  // end

#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] Running LFRA on flow "
    << f->id.src_ip << ":" << f->id.src_port << " -> " 
    << f->id.dst_ip << ":" << f->id.dst_port << std::endl;
#endif

  const Ipv4 * const ip = GetIpv4Header(pkt);
  const Tcp * const tcp = (Tcp *)(((const char *)ip) + (ip->header_length * 4));
  uint32_t seq = tcp->seq_num.value();

#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] LFRA: incoming SEQ " << seq 
    << ", expected_next " << f->expected_next << std::endl;
#endif

  if (before(seq, f->expected_next) || seq == f->expected_next) {

#ifdef _MY_DEBUG_
    std::cerr << "[DEBUG] LFRA: Case in sequence" << std::endl;
#endif

    Enqueue(f, pkt, err);
    UpdateExpected(f, pkt);

    if (!f->pq.empty()) {
      bess::Packet * p = f->pq.top();
      while (LFRArr::GetSeq(p) == f->expected_next) {
        f->pq.pop();

        Enqueue(f, p, err);
        UpdateExpected(f, p);

        if (!f->pq.empty()) {
          p = f->pq.top();
        }
        else {
          break;
        }
      }
    }
  }

  // ELSE IF(re-sequencing buffer is not full)
  // begin
  //   Store packet in re-sequencing buffer
  // end
  else if (f->pq.size() < max_ofo_buffsize_) {

#ifdef _MY_DEBUG_
    std::cerr << "[DEBUG] LFRA: re-sequencing buffer is not full" << std::endl;
#endif
    f->pq.push(pkt);

  }

  // ELSE // re-sequencing buffer is full
  // begin
  //   Select packet in buffer with lowest sequence number.
  //   IF (selected_packet_num less than current_packet_num) 
  //   begin
  //     Release selected packet into the output queue.
  //     Store current packet in the buffer.
  //   end
  //   ELSE
  //   begin
  //     Release current packet into the output queue.
  //   end 
  // end
  
  else {
#ifdef _MY_DEBUG_
    std::cerr << "[DEBUG] LFRA: re-sequencing buffer full" << std::endl;
#endif

    bess::Packet * p = f->pq.top();
    uint32_t lowest_seq = LFRArr::GetSeq(p);

    if (lowest_seq <= seq) {

      f->pq.pop();

      Enqueue(f, p, err);
      UpdateExpected(f, p);

      // modification: output all the consecutive packets
      if (!f->pq.empty()) {
        bess::Packet * p = f->pq.top();
        while (LFRArr::GetSeq(p) == f->expected_next) {
          f->pq.pop();

          Enqueue(f, p, err);
          UpdateExpected(f, p);
          
          if (!f->pq.empty()) {
            p = f->pq.top();
          }
          else {
            break;
          }
        }
      }
      
      f->pq.push(pkt);
      
    }

    else {
      Enqueue(f, pkt, err);
    }
  }
  f->timer = get_epoch_time();

  return;
}

void LFRArr::UpdateExpected(Flow * f, bess::Packet * p) {
  const Ipv4 * const ip = GetIpv4Header(p);
  const Tcp * const tcp = (const Tcp *)(((const char *)ip) + (ip->header_length * 4));
  uint32_t seq = tcp->seq_num.value();
  uint16_t psize = ip->length.value() - ((unsigned int)ip->header_length + tcp->offset) * 4;

#ifdef _MY_DEBUG_
  uint32_t old_en = f->expected_next;
#endif
  if (tcp->flags & Tcp::Flag::kSyn) {
    f->expected_next = seq + 1;
  }
  else {
    f->expected_next = seq + psize;
  }
#ifdef _MY_DEBUG_
  std::cerr << "[DEBUG] UpdateExpectedNext: expected_next updated from "
    << old_en << " to " << f->expected_next << std::endl;
#endif
}

// static inline int InsertOrEnqueue(Flow * f,
//                              bess::Packet * pkt, 
//                              uint32_t seq, 
//                              uint16_t seg_size,
//                              int * err) {

//   struct rb_node **new_node = &(fbuf->root.rb_node), *parent = NULL;

//   // Figure out where to put new_node node 
//   // if this sequence number somehow collide with an existing one, 
//   // let this one out. 
//   while (*new_node) {
//     struct nfq_flowdata *curr = container_of(*new_node, struct nfq_flowdata, node);

//     parent = *new_node;
//     if (before(seq, curr->seq))
//       new_node = &((*new_node)->rb_left);
//     else if (after(seq, curr->seq))
//       new_node = &((*new_node)->rb_right);

//     // retransmit. leave the larger or newer packet...
//     else {
//       int ret;
//       if (curr->seg_size > seg_size) {
//         ret = nfq_set_verdict(queue, packet_id, NF_DROP, 0, NULL);
//       }
//       else {
//         uint32_t oldid = curr->packet_id;
//         curr->packet_id = packet_id;
//         curr->seg_size =  seg_size;
//         ret = nfq_set_verdict(queue, oldid, NF_DROP, 0, NULL);
//       }
//       fbuf->last_activity = ev_now(EV_A);
//       return ret;
//     }
//   }

//   // do insertion

//   fbuf->size++;
//   struct nfq_flowdata * newdata = calloc(sizeof(struct nfq_flowdata), 1);
//   newdata->seq = seq;
//   newdata->packet_id = packet_id;
//   newdata->seg_size = seg_size;

//   struct rb_node * currfirst = rb_first(&(fbuf->root));
//   /* Add new_node node and rebalance tree. */
//   rb_link_node(&newdata->node, parent, new_node);
//   rb_insert_color(&newdata->node, &(fbuf->root));
//   fbuf->last_activity = ev_now(EV_A);

//   return 0;

// }

const Ipv4 * LFRArr::GetIpv4Header(const bess::Packet * const pkt) const {
  const Ethernet *eth = pkt->head_data<const Ethernet *>();
  return (const Ipv4 *)(eth + 1);
}

const Tcp * LFRArr::GetTCPHeader(const bess::Packet * const pkt) const {
  const Ethernet *eth = pkt->head_data<const Ethernet *>();
  const Ipv4 *ip = (const Ipv4 *)(eth + 1);
  return (const Tcp *)(((const char *)ip) + (ip->header_length * 4));
}

uint32_t LFRArr::GetSeq(const bess::Packet* const pkt) {
  const Ethernet *eth = pkt->head_data<const Ethernet *>();
  const Ipv4 *ip = (const Ipv4 *)(eth + 1);
  const Tcp *tcp =
    (const Tcp *)(((const char *)ip) + (ip->header_length * 4));
  return tcp->seq_num.value();
}

// uint16_t LFRArr::GetSize(const bess::Packet* const pkt) const {
//   const Ethernet *eth = pkt->head_data<const Ethernet *>();
//   const Ipv4 *ip = (const Ipv4 *)(eth + 1);
//   const Tcp *tcp =
//     (const Tcp *)(((const char *)ip) + (ip->header_length * 4));
//   return tcp->seq_num.value();
// }

llring *LFRArr::ResizeQueue(llring *old_queue, uint32_t new_size, int *err) {
  llring *new_queue = AddQueue(new_size, err);
  if (*err != 0) {
    return nullptr;
  }

  // migrates packets from the old queue
  if (old_queue) {
    bess::Packet *pkt;

    while (llring_dequeue(old_queue, reinterpret_cast<void **>(&pkt)) == 0) {
      *err = llring_enqueue(new_queue, pkt);
      if (*err == -LLRING_ERR_NOBUF) {
        bess::Packet::Free(pkt);
        *err = 0;
      } else if (*err != 0) {
        std::free(new_queue);
        return nullptr;
      }
    }

    std::free(old_queue);
  }
  return new_queue;
}


CommandResponse LFRArr::SetMaxFlowQueueSize(uint32_t queue_size) {
  if (queue_size == 0) {
    return CommandFailure(EINVAL, "max queue size must be at least 1");
  }
  max_queue_size_ = queue_size;
  return CommandSuccess();
}

CommandResponse LFRArr::SetOOQueueSize(uint32_t queue_size) {
  if (queue_size == 0) {
    return CommandFailure(EINVAL, "max queue size must be at least 1");
  }
  max_ofo_buffsize_ = queue_size;
  return CommandSuccess();
}

CommandResponse LFRArr::SetFlowTimeout(double tout) {
  if (tout <= 0) {
    return CommandFailure(EINVAL, "Flow timeout must be positive");
  }
  flow_timeout_ = tout;
  return CommandSuccess();
}

CommandResponse LFRArr::SetMaxFlowNum(uint32_t flow_n) {
  if (flow_n == 0) {
    return CommandFailure(EINVAL, "max flow number must be at least 1");
  }
  max_number_flows_ = flow_n;
  return CommandSuccess();

}

ADD_MODULE(LFRArr, "LFRArr", "Lowest first re sequencing algorithm")

