Network KPI calculates the uplink and downlink latencies between the 5G gNB and the UPF. Then, it sends the collected data to mongodb.
The data (in JSON) has the following format:
- _id (object id)
- packet_id (TCP packet id)
- scr (src IP)
- dst (dst IP)
- timestamp1 (time of sending the packet)
- direction (donwlink or uplink)
- delay (in milli-seconds - if this field does not exists, then the packet has not been received aka dropped)
- timestamp2 (time of receiving the packet - could be missing if the packet is dropped)
Both IP addresses should be known in advance and inputed in the /tools/constants.py script.
The script also calculates the percentage of dropped packets between the above mentioned elements.

To run the scrip:
1) clone this repository on both machines (gNB and UPF)
2) update the /tools/constants.py file (Filter type, IP addresses, URI to connect to mongodb, etc.)
3) On one of the machines (freely select one), comment lines 6(timer), 12(timer) and 42(dropped packets). The timer needs to run on only one machine, as well as the insertion of the dropped packets in the database.
4) Run the scripts on each machines

cleandb.py deletes all collections in the database unless the user specifies the name of the collections to drop:
cleandb.py -c [collection_name1, collection_name2, ...]
