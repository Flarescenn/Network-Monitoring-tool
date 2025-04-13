#include <iostream>
#include "npcap_wrapper.cpp"  
#include <string>
#include <vector>

int main() {
    try {
        npcap_wrapper sniffer;
        
        // Test listing interfaces
        std::cout << "Listing network interfaces:\n";
        auto interfaces = sniffer.list_interfaces();
        
        if (interfaces.empty()) {
            std::cout << "No interfaces found!\n";
            return 0;
        }
        int counter = 1;
        for (const auto& ifc : interfaces) {
            std::cout << counter++ << std::endl;
            std::cout << "Name: " << ifc.name << "\n";
            std::cout << "Description: " << ifc.desc << "\n";
            std::cout << "Address: " << ifc.addr << "\n";
            std::cout << "------------------------\n";
        }
        int choice = 0;
        std::cout<<"Enter an interface to listen on: "<<std::endl;
        std::cin>>choice;

        // Uncomment to test more functionality
        
        // Open the first interface for testing
        std::cout << "Opening connection to: " << interfaces[choice-1].desc << std::endl;
        sniffer.open_connection(interfaces[choice-1].name);
        std::string filter;
        std::cout << "Choose a filter: " << std::endl;
        std::cin >> filter;
        sniffer.filter_packets(filter);

        for (int i = 0; i < 5; i++){
            std::cout << "\nWaiting for packet...\n";
            auto packet = sniffer.fetch_packet();

            if (packet.data.size() > 0){
                std::cout << "Packet length: " << packet.length << std::endl;
                //std::cout << "Packet data: " << packet.data[0] << std::endl;
            } else {
                std::cout << "Time out" << std::endl;
            }
        }
        sniffer.close_connection();
  
        // Apply a simple filter

        
        
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}