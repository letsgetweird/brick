# Test PCAPs

Sample packet captures for testing Brick.

## Files

- **modbus-sample.pcap** - Modbus TCP traffic
- **enip-sample.pcap** - EtherNet/IP and CIP traffic
- **s7comm-sample.pcap** - Siemens S7comm traffic

## Usage

1. Start Brick: `./reset.sh`
2. Open http://localhost:8080
3. Upload any of these PCAPs via the web interface
4. View discovered ICS assets

## Sources

These samples are from public repositories:

- **Modbus**: [ICS-pcap project](https://github.com/automayt/ICS-pcap/blob/master/MODBUS/MODBUS-TestDataPart1/MODBUS-TestDataPart1.pcap) by automayt
- **ENIP**: [ICS-pcap project](https://github.com/automayt/ICS-pcap/blob/master/ETHERNET_IP/digitalbond%20pcaps/CL5000EIP-Change-Date-Attempt/CL5000EIP-Change-Date-Attempt.pcap) by automayt
- **S7**: [ICS-pcap project](https://github.com/automayt/ICS-pcap/blob/master/S7/s7comm_reading_setting_plc_time/s7comm_reading_setting_plc_time.pcap) by automayt

All samples are publicly available and used for testing and educational purposes only.
