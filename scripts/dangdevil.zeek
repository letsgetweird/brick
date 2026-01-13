@load base/protocols/conn
@load packages  # This loads all zkg-installed packages

export {
    redef enum Log::ID += { ASSET_LOG };
    
    type AssetRecord: record {
        ts:  time   &log;
        ip:  addr   &log;
        mac: string &log &optional;
    };
}

event zeek_init() {
    print "DANGDEVIL LOADED - ICS PROTOCOLS: Modbus, EtherNet/IP, S7comm";
    Log::create_stream(ASSET_LOG, [$columns=AssetRecord, $path="asset_log"]);
}

event connection_state_remove(c: connection) {
    local t = network_time();
    
    # Log originator
    local orig_rec: AssetRecord = [$ts=t, $ip=c$id$orig_h];
    if ( c$orig?$l2_addr ) {
        orig_rec$mac = c$orig$l2_addr;
    }
    Log::write(ASSET_LOG, orig_rec);
    
    # Log responder  
    local resp_rec: AssetRecord = [$ts=t, $ip=c$id$resp_h];
    if ( c$resp?$l2_addr ) {
        resp_rec$mac = c$resp$l2_addr;
    }
    Log::write(ASSET_LOG, resp_rec);
}

event zeek_done() {
    Log::flush(ASSET_LOG);
}
