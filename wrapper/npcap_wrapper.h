#pragma once
#include <pcap.h>
#include <string>
#include <vector>
#include <stdexcept>

class npcap_wrapper{
private:
    pcap_t* handle;                 // points to the session. closed every connection      
    char err_buff[PCAP_ERRBUF_SIZE];    //error-buffer for storing error messages
    bool capture_running;               

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

    //methods
    std::vector<interface_info> list_interfaces(); //list available interfaces
    void open_connection(const std::string& interface_name);
    void close_connection();
    packet_info fetch_packet(); 
    void fetch_loop();          
    void close_loop();
    bool filter_packets(const std::string filter);
    
};