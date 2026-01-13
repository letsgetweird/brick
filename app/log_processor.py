import os
import json
from database import update_asset, update_protocol, update_connection

ZEEK_LOG_PATH = os.getenv('ZEEK_LOG_PATH', '/data/zeek_logs')

def is_broadcast_or_multicast(ip):
    """Filter out broadcast and multicast addresses"""
    if ip.endswith('.255'):
        return True
    if ip.startswith(('224.', '225.', '226.', '227.', '228.', '229.', 
                      '230.', '231.', '232.', '233.', '234.', '235.', 
                      '236.', '237.', '238.', '239.')):
        return True
    return False

def parse_asset_log():
    """Parse the custom asset_log.log created by dangdevil.zeek"""
    asset_log = os.path.join(ZEEK_LOG_PATH, 'asset_log.log')
    
    if not os.path.exists(asset_log) or os.path.getsize(asset_log) == 0:
        return
    
    try:
        with open(asset_log, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                    
                try:
                    data = json.loads(line)
                    ip = data.get('ip')
                    mac = data.get('mac', '')
                    ts = data.get('ts')
                    
                    if ip and not is_broadcast_or_multicast(ip):
                        if mac and mac.lower() != 'ff:ff:ff:ff:ff:ff':
                            update_asset(ip, mac if mac else None, ts)
                        elif not mac:
                            update_asset(ip, None, ts)
                        
                except json.JSONDecodeError:
                    continue
        
        open(asset_log, 'w').close()
        
    except Exception as e:
        print(f"Asset log parsing error: {e}")

def parse_conn_log():
    """Parse conn.log for protocol and connection information"""
    conn_log = os.path.join(ZEEK_LOG_PATH, 'conn.log')
    if not os.path.exists(conn_log) or os.path.getsize(conn_log) == 0:
        return
    
    try:
        with open(conn_log, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                    
                try:
                    data = json.loads(line)
                    orig_ip = data.get('id.orig_h')
                    resp_ip = data.get('id.resp_h')
                    resp_port = data.get('id.resp_p')
                    proto = data.get('proto', 'unknown').upper()
                    service = data.get('service', '')
                    
                    if is_broadcast_or_multicast(orig_ip) or is_broadcast_or_multicast(resp_ip):
                        continue
                    
                    if orig_ip:
                        update_asset(orig_ip)
                        update_protocol(orig_ip, proto)
                        if service:
                            update_protocol(orig_ip, service.upper())
                    
                    if resp_ip:
                        update_asset(resp_ip)
                        update_protocol(resp_ip, proto)
                        if service:
                            update_protocol(resp_ip, service.upper())
                    
                    if orig_ip and resp_ip and resp_port:
                        update_connection(orig_ip, resp_ip, resp_port, proto)
                        
                except json.JSONDecodeError:
                    continue
        
        open(conn_log, 'w').close()
        
    except Exception as e:
        print(f"Conn log parsing error: {e}")

def parse_ics_logs():
    """Parse ICS-specific protocol logs (Modbus, EtherNet/IP, S7comm)"""
    # All three CISA ICSNPP plugins
    ics_logs = ['modbus.log', 'enip.log', 's7comm.log']
    
    for log_name in ics_logs:
        log_path = os.path.join(ZEEK_LOG_PATH, log_name)
        
        if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
            continue
        
        # Extract protocol name from filename
        protocol_name = log_name.replace('.log', '').upper()
        
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    try:
                        data = json.loads(line)
                        orig_ip = data.get('id.orig_h')
                        resp_ip = data.get('id.resp_h')
                        
                        # Update assets and mark them with the ICS protocol
                        if orig_ip and not is_broadcast_or_multicast(orig_ip):
                            update_asset(orig_ip)
                            update_protocol(orig_ip, protocol_name)
                        
                        if resp_ip and not is_broadcast_or_multicast(resp_ip):
                            update_asset(resp_ip)
                            update_protocol(resp_ip, protocol_name)
                    
                    except json.JSONDecodeError:
                        continue
            
            # Clear log after processing
            open(log_path, 'w').close()
            
        except Exception as e:
            print(f"ICS log parsing error ({log_name}): {e}")
