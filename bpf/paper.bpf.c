#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义一个 Map 来存储队列长度和其他统计信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);  // 只存一个队列长度
    __type(key, struct request *);      
    __type(value, struct io_stats); // 值是统计信息结构体
} stats_map SEC(".maps");

//这个map用来存储complete里面的计数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);  // 只存一个队列长度
    __type(key,u32);     
    __type(value, u64); // 值是统计信息结构体,前32位存储队列深度的累积值，后32位存储事件触发的次数（计数）
} issue_map SEC(".maps");

//这个map用来存储complete里面的计数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);  // 只存一个队列长度
    __type(key,u32);      
    __type(value, u32); // 值是统计信息结构体
} complete_map SEC(".maps");

// 定义环形缓冲区，用于将统计信息传递到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB 的环形缓冲区
} rb1 SEC(".maps");

// 定义统计信息的结构体
struct io_stats {
    u64 total_write_bytes;     // 总写入字节数
    u64 end_time;     // I/O结束时间
    u64 start_time;           // 统计开始时间
    u64 total_io_requests;    //总I/O请求数
};

// 处理 I/O 开始事件
SEC("kprobe/blk_account_io_start")
int trace_blk_account_io_start(struct pt_regs *ctx) {
    u64 time = bpf_ktime_get_ns();
    //初始化统计信息
    struct io_stats stats = {};
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);

    stats.start_time = time;
    //读取数据大小
    u64 data_len = 0;
    bpf_core_read(&data_len, sizeof(data_len), &req->__data_len);

    stats.total_write_bytes = data_len;
    bpf_map_update_elem(&stats_map, &req, &stats, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq) {
    u32 key = 0;  // 使用 key = 0 来查询 map
    struct request_queue *q;
    bpf_core_read(&q, sizeof(q), &rq->q);
    if(!q){
        bpf_printk("block_rq_issue is not found queue\n");
        return 0;
    }

    // 提取队列深度
    unsigned int queue_len = 0;
    bpf_core_read(&queue_len, sizeof(queue_len), &q->queue_depth);  // 获取队列深度
    if(queue_len == 0){
        bpf_printk("block_rq_issue is not found queue_len\n");
        return 0;
    }
    
    //查找现有的数据（队列深度和事件计数）
    u64 *data = bpf_map_lookup_elem(&issue_map, &key);
    if(!data){
        //如果没有找到数据，初始化队列深度和计数
        u64 initial = ((u64)queue_len << 32) | 1; //存储队列深度在高32位
        bpf_map_update_elem(&issue_map,&key,&initial,BPF_ANY);
    }else{
        //如果找到数据，更新队列深度和计数
        u64 current_data = *data;
        
        // 从 current_data 中提取队列深度和事件计数
        unsigned int current_queue_len = current_data >> 32; // 高32位为队列深度
        unsigned int current_count = current_data & 0xFFFFFFFF; // 低32位为事件计数
        
        // 更新队列深度和计数
        current_queue_len += queue_len;  // 累加队列深度
        current_count += 1;              // 累加事件计数

        // 合并成新的 u64：高32位为队列深度，低32位为计数
        u64 updated_data = ((u64)current_queue_len << 32) | (current_count & 0xFFFFFFFF);
        bpf_map_update_elem(&issue_map, &key, &updated_data, BPF_ANY);  // 更新 map 中的值
    }

    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error, unsigned int nr_bytes) {
    u32 key = 0;  // 使用 key = 0 来查询 map
    u32 *count = bpf_map_lookup_elem(&complete_map, &key);  // 查找 key 对应的值

    if (count) {
        (*count)++;  // 找到 count 后，进行自增操作
        // 更新 map 中的值
        bpf_printk("complete_count:%d\n",*count);
        bpf_map_update_elem(&complete_map, &key, count, BPF_ANY);  // 将修改后的 count 重新保存回 map
    } else {
        // 如果没有找到计数器，初始化为 1
        u32 initial = 1;
        bpf_map_update_elem(&complete_map, &key, &initial, BPF_ANY);  // 将 key 和初始值插入 map
    }
    return 0;
}

// 处理 I/O 完成事件
SEC("kprobe/blk_account_io_done")
int trace_blk_account_io_done(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);
    struct io_stats *stats = bpf_map_lookup_elem(&stats_map,&req);
    if(!stats){
        bpf_printk("blk_account_io_done is not found stats\n");
        return 0;
    }
    stats->end_time = ts;

    bpf_ringbuf_output(&rb1,stats,sizeof(*stats),0);
    return 0;
}

char _license[] SEC("license") = "GPL";

