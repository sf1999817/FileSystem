#include <unistd.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include "paper.skel.h"

FILE *output_file = NULL; // 文件指针

int issue_fd;

// 定义统计信息结构体
struct io_stats {
    long long total_write_bytes;     // 总写入字节数
    long long end_time;     // I/O结束时间
    long long start_time;           // 统计开始时间
    long long total_io_requests;    // 累计的 I/O 请求次数
};

// 用于存储每秒的数据统计
struct io_accumulated_stats {
    long long total_write_bytes;  // 累计的写入字节数
    long long last_time;          // 上次时间记录
    long long total_busy_time_ns;     // 累计的磁盘忙碌时间（纳秒）
};

// 初始化累计统计数据
struct io_accumulated_stats accumulated_stats = {0, 0, 0};

long long get_current_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);  // 获取当前系统时间
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;  // 转换为纳秒
}

// 事件处理函数
static int handle_event1(void *ctx, void *data, size_t data_sz) {
    struct io_stats *stats = data;

    long long current_time_ns = get_current_time_ns(); // 获取当前时间（纳秒）

    int complete_fd = *(int *)ctx;

    //打开文件，如果没有打开的话
    if(!output_file){
        output_file = fopen("normal.txt","w");
        if(!output_file){
            fprintf(stderr, "Failed to open output file\n");
            return 1;
        }
    }

    // 访问 complete_map 中的数据
    int key = 0;  // 根据需要设置 key，假设我们查找 key = 0
    int count = 0;  // 用来存储查询结果

    int key1 = 0;  // 根据需要设置 key，假设我们查找 key = 1
    long long count1 = 0;  // 用来存储查询结果

    // 如果是第一次执行，直接更新数据
    if (accumulated_stats.last_time == 0) {
        accumulated_stats.last_time = current_time_ns;
        accumulated_stats.total_write_bytes = stats->total_write_bytes;
        accumulated_stats.total_busy_time_ns = stats->end_time - stats->start_time; // 初始化忙碌时间
        return 0;
    }

    // 计算时间差
    long long time_diff_ns = current_time_ns - accumulated_stats.last_time;

    // 如果时间差已经超过1秒
    if (time_diff_ns >= 5000000000LL) {
        // 输出统计结果（单位：字节/秒）
        fprintf(output_file, "Accumulated write rate: %lld bytes/s\n", accumulated_stats.total_write_bytes);
        fflush(output_file);
        printf("Accumulated write rate: %lld bytes/s\n", accumulated_stats.total_write_bytes);

        // 计算磁盘利用率（单位：%）
        double disk_utilization = ((double)accumulated_stats.total_busy_time_ns / time_diff_ns) * 100;
        fprintf(output_file, "Disk utilization: %.2f%%\n", disk_utilization);
        fflush(output_file);
        printf("Disk utilization: %.2f%%\n", disk_utilization);

        // 通过文件描述符查询 map 中的值
        int ret = bpf_map_lookup_elem(complete_fd, &key, &count);
        if (ret == 0) {
            fprintf(output_file, "I/O requests: %d\n", count);  // 输出 map 中存储的计数器值
            fflush(output_file);
            printf("I/O requests: %d\n", count);  // 输出 map 中存储的计数器值
        } else {
            printf("No value found for key %d\n", key);
        }

        // 访问 issue_map 中的数据
        int ret1 = bpf_map_lookup_elem(issue_fd, &key1, &count1);
        if (ret1 == 0) {
            // 从 u64 数据中提取队列深度和事件计数
            unsigned int total_queue_len = count1 >> 32;  // 高32位是队列深度总和
            unsigned int event_count = count1 & 0xFFFFFFFF; // 低32位是事件计数
            if (event_count > 0) {
                float avg_queue_len = (float)total_queue_len / event_count;
                fprintf(output_file, "Average Queue Length: %f\n", avg_queue_len);
                fflush(output_file);
                printf("Average Queue Length: %f\n", avg_queue_len);
            } else {
                printf("No events recorded.\n");
            }
        } else {
            printf("No value found for key %d\n", key1);
        }

        // 重置内核中的计数器
        int zero = 0;
        bpf_map_update_elem(complete_fd, &key, &zero, BPF_ANY);
        bpf_map_update_elem(issue_fd, &key1, &zero, BPF_ANY);
        
        fprintf(output_file, "===============================================================\n");
        printf("===============================================================\n");

        // 重置累计统计数据
        accumulated_stats.last_time = current_time_ns;
        accumulated_stats.total_write_bytes = stats->total_write_bytes;
        accumulated_stats.total_busy_time_ns = 0; // 重置磁盘忙碌时间
    } else {
        // 否则，继续累加写入字节数
        accumulated_stats.total_write_bytes += stats->total_write_bytes;
        // 累加磁盘忙碌时间
        if (stats->start_time > 0 && stats->end_time > 0) {
            long long io_busy_time_ns = stats->end_time - stats->start_time;  // 当前 I/O 操作的忙碌时间
            accumulated_stats.total_busy_time_ns += io_busy_time_ns;  // 累加磁盘忙碌时间
        }
    }



    return 0;
}

int main(int argc, char **argv) {
    struct paper_bpf *skel;
    int err;

    // 加载和验证BPF程序
    skel = paper_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加BPF程序到内核探针
    err = paper_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        paper_bpf__destroy(skel);
        return 1;
    }

    int complete_fd = bpf_map__fd(skel->maps.complete_map);
    if(!complete_fd){
        fprintf(stderr, "Failed to get complete_fd\n");
        paper_bpf__destroy(skel);
        return 1;
    }

    issue_fd = bpf_map__fd(skel->maps.issue_map);
    if(!issue_fd){
        fprintf(stderr, "Failed to get issue_fd\n");
        paper_bpf__destroy(skel);
        return 1;
    }

    // 创建ring buffer
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb1), handle_event1, &complete_fd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        paper_bpf__destroy(skel);
        return 1;
    }

    // 处理事件
    while (1) {
        err = ring_buffer__poll(rb, 0 /* timeout, ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // 清理
    ring_buffer__free(rb);
    paper_bpf__destroy(skel);
    fclose(output_file);

    return 0;
}