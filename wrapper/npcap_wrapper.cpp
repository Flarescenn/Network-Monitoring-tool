#include <pcap.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include "npcap_wrapper.h"
// #include <pybind11/pybind11.h>
// #include <pybind11/stl.h>
//list_adapters --
//open_connection --
//fetch_packet --
//close_connection --
//filter_packets  --
// namespace py = pybind11;

npcap_wrapper::npcap_wrapper(){
        handle = nullptr;
        err_buff[0] = '\0';
        capture_running = false;
    }
npcap_wrapper::~npcap_wrapper() {
        if (handle) {
            pcap_close(handle); 
        }
    }

    //list_adapters function
std::vector<npcap_wrapper::interface_info> npcap_wrapper::list_interfaces(){
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
void npcap_wrapper::open_connection(const std::string& interface_name) {
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
void npcap_wrapper::close_connection() {
    if (handle != nullptr) {
        pcap_close(handle);
        handle = nullptr;
    }
}

npcap_wrapper::packet_info npcap_wrapper::fetch_packet(){
    if (!handle){
        throw std::runtime_error("No interface open!");
    }
    struct pcap_pkthdr* header;
    const u_char* data;
    int result = pcap_next_ex(handle, &header, &data);
    if (result == 1) { // success
        return { 
            header->ts.tv_sec, //timestamp
            header->caplen,    //length of the capture
            std::vector<uint8_t>(data, data + header->caplen) };  //data
    } 
    else if (result == 0) {         // Timeout expired
        return {};
    } 
    else {                          // Error(-1) or EOF(-2)
        throw std::runtime_error("Error capturing packet: " + std::string(pcap_geterr(handle)));
    }
}
//filter_packets
bool npcap_wrapper::filter_packets(const std::string& filter){
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

//static handler
void npcap_wrapper::pcap_packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    npcap_wrapper* instance = reinterpret_cast<npcap_wrapper*>(user_data);
    if (instance){
        instance->process_packet(header, pkt_data);
    }
}

void npcap_wrapper::process_packet(const struct pcap_pkthdr* header, const u_char* pkt_data){
    if (!capture_running) return; //return if no capturing
    packet_info info;
    info.timestamp = header->ts.tv_sec;
    info.length = header->caplen;
    
    std::lock_guard<std::mutex> lock(queue_mutex);
    packet_queue.push_back(std::move(info));
}

void npcap_wrapper::start_capture_loop(){
    if (!handle) throw std::runtime_error("No interfaces are open!");
    if (capture_running) std::cout << "The capture loop is already running" <<  std::endl;
    
    capture_running = true;
    
    capture_thread = std::thread([this](){
        // this thread would be blocked by the pcap_loop till breakloop
        int pcap_result  = pcap_loop(handle, -1, pcap_packet_handler, reinterpret_cast<u_char*>(this));
        //after pcap_loop returns
        capture_running = false;
        if (pcap_result == -1){
            std::cerr << "pcap loop error: " << pcap_geterr(handle) << std::endl;
        } else if (pcap_result == -2){
            std::cout << "The loop was terminated by pcap_breakloop." << std::endl;
        } else {
            std::cout << "Captured packets: " << pcap_result << std::endl;
        }
    });
    std::cout << "Capture loop started." << std::endl;
}

void npcap_wrapper::stop_capture_loop() {
    if (capture_running && handle) {
        capture_running = false; // Signal handler to stop processing new packets
                                   
        pcap_breakloop(handle);    
    }

    if (capture_thread.joinable()) {
        capture_thread.join(); // Wait for the capture thread to finish
        std::cout << "Capture thread joined." << std::endl;
    }
}

std::vector<npcap_wrapper::packet_info> npcap_wrapper::get_queued_packets() {
    std::vector<packet_info> packets_to_return;
    std::lock_guard<std::mutex> lock(queue_mutex); 
    if (!packet_queue.empty()) {
        packets_to_return.swap(packet_queue); // Efficiently move all packets
                                              // packet_queue is now empty
    }
    return packets_to_return;
}

// Python Bindings
// PYBIND11_MODULE(npcap_wrapper, m) {
//     py::class_<npcap_wrapper>(m, "npcap_wrapper")
//         .def(py::init<>())
//         .def("list_interfaces", &npcap_wrapper::list_interfaces)
//         .def("open_connection", &npcap_wrapper::open_connection)
//         .def("close_connection", &npcap_wrapper::close_connection)
//         .def("fetch_packets", &npcap_wrapper::fetch_packets)
//         .def("filter_packets", &npcap_wrapper::filter_packets);

//     py::class_<npcap_wrapper::interface_info>(m, "interface_info")
//         .def_readwrite("name", &npcap_wrapper::interface_info::name)
//         .def_readwrite("desc", &npcap_wrapper::interface_info::desc)
//         .def_readwrite("addr", &npcap_wrapper::interface_info::addr);

//     py::class_<npcap_wrapper::packet_info>(m, "packet_info")
//         .def_readwrite("timestamp", &npcap_wrapper::packet_info::timestamp)
//         .def_readwrite("length", &npcap_wrapper::packet_info::length)
//         .def_readwrite("data", &npcap_wrapper::packet_info::data);
// }