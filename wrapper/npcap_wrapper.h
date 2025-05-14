#pragma once
#include <pcap.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <atomic> //for atomic bool

class npcap_wrapper{
    public:
    npcap_wrapper();
    ~npcap_wrapper();

    struct interface_info {
        std::string name;
        std::string desc;
        std::string addr;
    };

    struct packet_info {
        time_t timestamp;
        uint32_t length;
        std::vector<uint8_t> data;
    };

    std::vector<packet_info> packet_queue;  //need to make this thread safe

    //methods
    std::vector<interface_info> list_interfaces(); //list available interfaces
    void open_connection(const std::string& interface_name);
    void close_connection();

    packet_info fetch_packet();  //fetches a single packet

    void start_capture_loop();          //fetches every packet till stopped, must spawn a new thread
    void stop_capture_loop();
    std::vector<packet_info> get_queued_packets();  //retrieve packets queued by the loop

    bool filter_packets(const std::string& filter);
    

private:
    pcap_t* handle;                 // points to the session. closes every connection      
    char err_buff[PCAP_ERRBUF_SIZE];    //error-buffer for storing error messages            
    
    std::thread capture_thread;
    std::mutex queue_mutex;
    std::atomic<bool> capture_running;

    void packet_handler(u_char* user,       //called by the start_capture_loop to handle packets
        const struct pcap_pkthdr* header,
        const u_char* pkt_data);
    
    static void pcap_packet_handler(u_char* user_data,          //C style callback for pcap_loop
                                const struct pcap_pkthdr* header,
                                const u_char* pkt_data);
    
    void process_packet(const struct pcap_pkthdr* header,       //called by the static handler
                                 const u_char* pkt_data);   

};
