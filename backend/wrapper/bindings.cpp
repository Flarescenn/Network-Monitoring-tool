#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "npcap_wrapper.h"

namespace py = pybind11;

PYBIND11_MODULE(npcap_module, m){
    m.doc() = "Python bindings for Npcap Wrapper";
    
    //interface_info struct
    py::class_<npcap_wrapper::interface_info>(m, "interface_info")
        .def(py::init<>())
        .def_readwrite("name", &npcap_wrapper::interface_info::name)
        .def_readwrite("desc", &npcap_wrapper::interface_info::desc)
        .def_readwrite("addr", &npcap_wrapper::interface_info::addr)
        .def("__repr__", [](const npcap_wrapper::interface_info &i) {
            return "<interface_info name='" + i.name + "' desc='" + i.desc + "' addr='" + i.addr + "'>";
    });

    //packet_info struct
    py::class_<npcap_wrapper::packet_info>(m, "packet_info")
        .def(py::init<>())
        .def_readwrite("timestamp", &npcap_wrapper::packet_info::timestamp)
        .def_readwrite("length", &npcap_wrapper::packet_info::length)
        // .def_property_readonly("data", &npcap_wrapper::packet_info::data) <--- This returns list. I prefer to use bytestream
        .def_property_readonly("data", [](const npcap_wrapper::packet_info &p) {
            return py::bytes(reinterpret_cast<const char*>(p.data.data()), p.data.size());
        })  //<-- This returns bytestream
        .def("__repr__", [](const npcap_wrapper::packet_info &p) {
            return "<packet_info timestamp='" + std::to_string(p.timestamp) + "' length='" + std::to_string(p.length) + "'>";
    });

    //npcap_wrapper class - all public methods
    py::class_<npcap_wrapper>(m, "npcap_wrapper")
        .def(py::init<>())

        .def("list_interfaces", &npcap_wrapper::list_interfaces, "List available network interfaces")

        .def("open_connection", &npcap_wrapper::open_connection, py::arg("interface_name"), 
             "Open a connection to the specified network interface")

        .def("close_connection", &npcap_wrapper::close_connection, "Closes the current connection")

        .def("fetch_packet", &npcap_wrapper::fetch_packet, py::call_guard<py::gil_scoped_release>(), 
            "Fetches a single packet")

        .def("start_capture_loop", &npcap_wrapper::start_capture_loop, py::call_guard<py::gil_scoped_release>(),
            "Starts the capture loop in a separate thread")

        .def("stop_capture_loop", &npcap_wrapper::stop_capture_loop, py::call_guard<py::gil_scoped_release>(),
            "Stops the packet capture loop")

        .def("get_queued_packets", &npcap_wrapper::get_queued_packets, "Retreive packets queued by the capture loop")

        .def("filter_packets", &npcap_wrapper::filter_packets, py::arg("filter stirng"), "Applies a filter to the current connection's packets");
}

