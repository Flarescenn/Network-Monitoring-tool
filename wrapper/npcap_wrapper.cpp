#include <pcap.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
//list_adapters --
//open_connection --
//fetch_packet --
//close_connection --
//filter_packets  --

class npcap_wrapper{
private:
    pcap_t* handle;
    char err_buff[PCAP_ERRBUF_SIZE];
    bool capture_running;
public:
    npcap_wrapper(){
        handle = nullptr;
        err_buff[0] = '\0';
        capture_running = false;
    }
    ~npcap_wrapper() {
        if (handle) {
            pcap_close(handle); 
        }
    }
    struct interface_info {
        std::string name;
        std::string desc;
        std::string addr;
    };

    //list_adapters function
    std::vector<interface_info> list_interfaces(){
        pcap_if_t* alldevs; //pointer to a linked list of all the network interfaces
        std::vector<interface_info> interfaces;

        if (pcap_findalldevs(&alldevs, err_buff) == -1) {
            // An error occurred, and errbuf contains the error message
            throw std::runtime_error("Error finding devices: " + std::string(err_buff));
        }

        //traverse the linked list
        for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next ){
            
            interface_info curr;
            curr.name = dev->name;

            if (dev->description){
                curr.desc = dev->description;
            }else curr.desc = "No Description Available!";

            if (dev->addresses){
                char ip_str[INET_ADDRSTRLEN];
                struct sockaddr_in* addr = (struct sockaddr_in*)dev->addresses->addr;
                inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
                curr.addr = ip_str;

            }else curr.addr = "No Addresses Available!";

            interfaces.push_back(curr);
        }
        pcap_freealldevs(alldevs);
        return interfaces;
    }
    //open_connection
    void open_connection(const std::string& interface_name) {
        close_connection();
        handle = pcap_open_live(interface_name.c_str(),
         65536,                     //makes sure the entire packet is captured
         1,                         //promiscious mode
         1000,                      //read timeout
         err_buff);
        if (!handle) {
            throw std::runtime_error("Error opening interface: " + std::string(err_buff));
        }
    }
    //close_connection
    void close_connection() {
        if (handle != nullptr) {
            pcap_close(handle);
            handle = nullptr;
        }
    }

    //fetch-packets
    struct packet_info {
        time_t timestamp;
        uint32_t length;
        std::vector<uint8_t> data;
    };
    packet_info fetch_packets(){
        if (!handle){
            throw std::runtime_error("No interface open!");
        }
        struct pcap_pkthdr* header;
        const u_char* data;
        int result = pcap_next_ex(handle, &header, &data);

        if (result == 1) { // success
            return { 
                header->ts.tv_sec, 
                header->caplen, 
                std::vector<uint8_t>(data, data + header->caplen) };
        } 
        else if (result == 0) {         // Timeout expired
            return {};
        } 
        else {                          // Error(-1) or EOF(-2)
            throw std::runtime_error("Error capturing packet: " + std::string(pcap_geterr(handle)));
        }
    }
    //filter_packets
    bool filter_packets(const std::string filter){
        if (!handle){
            throw std::runtime_error("No interface open!");
        }
        struct bpf_program fp;
        
        // Compile the filter
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            throw std::runtime_error("Could not compile filter: " + 
                                      std::string(pcap_geterr(handle)));
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            pcap_freecode(&fp);
            throw std::runtime_error("Could not set filter: " + 
                                      std::string(pcap_geterr(handle)));
        }

        pcap_freecode(&fp);
        return true;
    }
    //capture-loop for efficiency and reducing Python-C++ comm. overhead

};