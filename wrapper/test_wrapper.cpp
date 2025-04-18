#include <iostream>
#include "npcap_wrapper.cpp"  
#include <string>
#include <vector>
using std::cout, std::cin, std::endl;
int main() {
    try {
        npcap_wrapper sniffer;
        
        // Test listing interfaces
        cout << "Listing network interfaces:\n";
        auto interfaces = sniffer.list_interfaces();
        
        if (interfaces.empty()) {
            cout << "No interfaces found!\n";
            return 0;
        }
        int counter = 1;
        for (const auto& ifc : interfaces) {
            cout << counter++ << endl;
            cout << "Name: " << ifc.name << "\n";
            cout << "Description: " << ifc.desc << "\n";
            cout << "Address: " << ifc.addr << "\n";
            cout << "------------------------\n";
        }
        int choice = 0;
        cout<<"Enter an interface to listen on: "<<endl;
        cin>>choice;

        // Uncomment to test more functionality
        
        // Open the first interface for testing
        cout << "Opening connection to: " << interfaces[choice-1].desc << endl;
        sniffer.open_connection(interfaces[choice-1].name);
        // std::string filter;
        // cout << "Choose a filter: " << endl;
        // cin >> filter;
        // sniffer.filter_packets(filter);

        for (int i = 0; i < 5; i++){
            cout << "\nWaiting for packet...\n";
            auto packet = sniffer.fetch_packet();

            if (packet.data.size() > 0){
                cout << "Packet length: " << packet.length << endl;
                //cout << "Packet data: " << packet.data[0] << endl;
            } else {
                cout << "Time out" << endl;
            }
        }
        sniffer.close_connection();

        
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}