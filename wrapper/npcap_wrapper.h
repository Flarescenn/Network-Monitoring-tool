#pragma once
#include <pcap.h>
#include <string>
#include <vector>
#include <stdexcept>


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

    std::vector<packet_info> packet_queue;  

    //methods
    std::vector<interface_info> list_interfaces(); //list available interfaces
    void open_connection(const std::string& interface_name);
    void close_connection();
    packet_info fetch_packet();  //fetches a single packet
    void fetch_loop();          //fetches every packet till stopped
    void close_loop();
    bool filter_packets(const std::string filter);
    

private:
    pcap_t* handle;                 // points to the session. closes every connection      
    char err_buff[PCAP_ERRBUF_SIZE];    //error-buffer for storing error messages
    bool capture_running;               //used in fecth_loop 
    
    void packet_handler(u_char* user,       //called by the fetch_loop to handle packets
        const struct pcap_pkthdr* header,
        const u_char* pkt_data);
    
    std::function<void(const packet_info&)> user_callback;

};
