@load base/protocols/conn
@load packages  # This loads all zkg-installed packages

export {
    redef enum Log::ID += { ASSET_LOG };
    
    type AssetRecord: record {
        ts:  time   &log;
        ip:  addr   &log;
        mac: string &log &optional;
    };
    
    global seen_assets: table[addr] of AssetRecord &create_expire = 1 day;
}

event zeek_init() {
    print "DANGDEVIL LOADED - ICS PROTOCOLS: Modbus, EtherNet/IP, S7comm";
    Log::create_stream(ASSET_LOG, [$columns=AssetRecord, $path="asset_log"]);
}

# Log assets from new connections (works better for PCAPs)
event new_connection(c: connection) {
    local t = network_time();
    
    # Log originator if not seen before
    if ( c$id$orig_h !in seen_assets ) {
        local orig_rec: AssetRecord = [$ts=t, $ip=c$id$orig_h];
        if ( c$orig?$l2_addr ) {
            orig_rec$mac = c$orig$l2_addr;
        }
        seen_assets[c$id$orig_h] = orig_rec;
        Log::write(ASSET_LOG, orig_rec);
    }
    
    # Log responder if not seen before
    if ( c$id$resp_h !in seen_assets ) {
        local resp_rec: AssetRecord = [$ts=t, $ip=c$id$resp_h];
        if ( c$resp?$l2_addr ) {
            resp_rec$mac = c$resp$l2_addr;
        }
        seen_assets[c$id$resp_h] = resp_rec;
        Log::write(ASSET_LOG, resp_rec);
    }
}

# Also try connection_state_remove for good measure
event connection_state_remove(c: connection) {
    local t = network_time();
    
    # Log originator if not already logged
    if ( c$id$orig_h !in seen_assets ) {
        local orig_rec: AssetRecord = [$ts=t, $ip=c$id$orig_h];
        if ( c$orig?$l2_addr ) {
            orig_rec$mac = c$orig$l2_addr;
        }
        seen_assets[c$id$orig_h] = orig_rec;
        Log::write(ASSET_LOG, orig_rec);
    }
    
    # Log responder if not already logged
    if ( c$id$resp_h !in seen_assets ) {
        local resp_rec: AssetRecord = [$ts=t, $ip=c$id$resp_h];
        if ( c$resp?$l2_addr ) {
            resp_rec$mac = c$resp$l2_addr;
        }
        seen_assets[c$id$resp_h] = resp_rec;
        Log::write(ASSET_LOG, resp_rec);
    }
}

event zeek_done() {
    print fmt("DANGDEVIL: Logged %d unique assets", |seen_assets|);
    Log::flush(ASSET_LOG);
}
