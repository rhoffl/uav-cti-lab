# ============================================================
# UAV CTI Lab — Zeek MAVLink Protocol Analyzer
# File: docker/configs/zeek/scripts/mavlink-monitor.zeek
#
# DEFENSIVE PURPOSE: Parses MAVLink UDP streams to generate
# structured logs for SIEM correlation and CTI enrichment.
#
# Citation [6]: Rodday et al. (2016) "Exploring Security
#   Vulnerabilities of UAVs." IEEE NOMS 2016.
# ============================================================

module MAVLink;

export {
    redef enum Log::ID += { LOG };

    # Log record for each observed MAVLink message
    type Info: record {
        ts:           time    &log;
        uid:          string  &log;
        id:           conn_id &log;
        msg_len:      count   &log &optional;
        msg_seq:      count   &log &optional;
        sys_id:       count   &log &optional;   # Sender system ID
        comp_id:      count   &log &optional;   # Sender component ID
        msg_id:       count   &log &optional;   # MAVLink message type
        msg_name:     string  &log &optional;   # Human-readable name
        is_v2:        bool    &log &default=F;  # MAVLink v2?
        anomaly:      string  &log &optional;   # Anomaly description
    };

    # Known high-risk message IDs for monitoring
    const MONITORED_MSG_IDS: set[count] = {
        11,   # SET_MODE  — flight mode changes
        76,   # COMMAND_LONG  — arbitrary command injection
        84,   # SET_POSITION_TARGET_GLOBAL_INT — waypoint override
        179,  # SET_ACTUATOR_CONTROL_TARGET — direct motor control
        192,  # DO_SET_HOME — home position override
        400,  # ARM/DISARM (via COMMAND_LONG param)
    } &redef;

    # Map message IDs to human-readable names
    const MSG_NAMES: table[count] of string = {
        [0]   = "HEARTBEAT",
        [1]   = "SYS_STATUS",
        [11]  = "SET_MODE",
        [30]  = "ATTITUDE",
        [32]  = "LOCAL_POSITION_NED",
        [33]  = "GLOBAL_POSITION_INT",
        [65]  = "RC_CHANNELS",
        [74]  = "VFR_HUD",
        [76]  = "COMMAND_LONG",
        [77]  = "COMMAND_ACK",
        [84]  = "SET_POSITION_TARGET_GLOBAL_INT",
        [87]  = "POSITION_TARGET_GLOBAL_INT",
        [111] = "TIMESYNC",
        [179] = "SET_ACTUATOR_CONTROL_TARGET",
        [192] = "MAV_CMD_DO_SET_HOME",
        [253] = "STATUSTEXT",
    } &default = "UNKNOWN";
}

# Per-connection state for sequence number tracking
global conn_state: table[string] of record {
    last_seq:    count;
    src_sys_id:  count;
    msg_count:   count;
    start_time:  time;
};

# ── Log initialization ───────────────────────────────────────
event zeek_init() {
    Log::create_stream(MAVLink::LOG, [$columns=Info, $path="mavlink"]);
    print "MAVLink analyzer loaded — monitoring ports 14550-14560/UDP";
}

# ── UDP payload inspection ────────────────────────────────────
event udp_contents(c: connection, is_orig: bool, contents: string) {

    # Only inspect traffic on MAVLink ports
    local dport = c$id$resp_p;
    if ( dport < 14550/udp || dport > 14560/udp ) return;
    if ( |contents| < 8 ) return;

    local rec = Info(
        $ts  = network_time(),
        $uid = c$uid,
        $id  = c$id
    );

    local magic = bytestring_to_count(contents[0], T);
    local is_v2 = (magic == 0xFD);
    local is_v1 = (magic == 0xFE);

    if ( !is_v1 && !is_v2 ) return;

    rec$is_v2   = is_v2;
    rec$msg_len = bytestring_to_count(contents[1], T);

    if ( is_v1 && |contents| >= 6 ) {
        rec$msg_seq  = bytestring_to_count(contents[2], T);
        rec$sys_id   = bytestring_to_count(contents[3], T);
        rec$comp_id  = bytestring_to_count(contents[4], T);
        rec$msg_id   = bytestring_to_count(contents[5], T);
        rec$msg_name = MSG_NAMES[rec$msg_id];
    }
    else if ( is_v2 && |contents| >= 10 ) {
        rec$msg_seq = bytestring_to_count(contents[4], T);
        rec$sys_id  = bytestring_to_count(contents[5], T);
        rec$comp_id = bytestring_to_count(contents[6], T);
        # MAVLink v2 uses 3-byte msg_id
        rec$msg_id  = bytestring_to_count(contents[7], T) +
                      bytestring_to_count(contents[8], T) * 256 +
                      bytestring_to_count(contents[9], T) * 65536;
        rec$msg_name = MSG_NAMES[rec$msg_id];
    }

    # ── Anomaly detection ──────────────────────────────────────

    # Flag high-risk command types
    if ( rec?$msg_id && rec$msg_id in MONITORED_MSG_IDS ) {
        rec$anomaly = fmt("HIGH_RISK_MSG:%s from sys_id=%d",
                          rec$msg_name, rec?$sys_id ? rec$sys_id : 0);
        NOTICE([$note=Notice::Weird,
                $conn=c,
                $msg=fmt("MAVLink high-risk message: %s", rec$anomaly)]);
    }

    # Detect sequence number gaps (potential replay/injection)
    if ( rec?$msg_seq && rec?$sys_id ) {
        local key = fmt("%s-%d", c$uid, rec$sys_id);
        if ( key in conn_state ) {
            local st = conn_state[key];
            local expected = (st$last_seq + 1) % 256;
            if ( rec$msg_seq != expected ) {
                local gap = (rec$msg_seq > st$last_seq) ?
                            rec$msg_seq - st$last_seq - 1 :
                            256 - st$last_seq + rec$msg_seq - 1;
                if ( gap > 2 ) {
                    rec$anomaly = fmt("SEQ_GAP:expected=%d,got=%d,gap=%d",
                                      expected, rec$msg_seq, gap);
                }
            }
            conn_state[key]$last_seq = rec$msg_seq;
            conn_state[key]$msg_count += 1;
        } else {
            conn_state[key] = [
                $last_seq   = rec$msg_seq,
                $src_sys_id = rec$sys_id,
                $msg_count  = 1,
                $start_time = network_time()
            ];
        }
    }

    Log::write(MAVLink::LOG, rec);
}

# ── Heartbeat rate monitoring ─────────────────────────────────
# MAVLink spec: 1 Hz heartbeat. >10 Hz from same source = anomaly.
global heartbeat_count: table[addr] of count &default=0;
global heartbeat_window_start: table[addr] of time;

event zeek_done() {
    print "MAVLink analyzer shutdown — logs in mavlink.log";
}
