# Run with -b: only connection bookkeeping, not the usual application policies.
@load base/protocols/conn

module Monitor;

export {
    type PortRange: record {
        first: count;
        last: count;
    };
    # 0.0.0.0 and [::] are family-specific LOCAL wildcard keys, not literal hosts.
    const local_hosts: set[addr] = set() &redef;
    const rules: table[addr, transport_proto] of vector of PortRange = table() &redef;
}

# Keep the logging event alive, but do not create default business/diagnostic logs.
redef Log::enable_local_logging = F;
redef Log::enable_remote_logging = F;

function matches_rule(host: addr, endpoint: port, proto: transport_proto): bool
    {
    if ( [host, proto] !in rules )
        return F;
    local n = port_to_count(endpoint);
    for ( i, bounds in rules[host, proto] )
        if ( n >= bounds$first && n <= bounds$last )
            return T;
    return F;
    }

function is_server(host: addr, endpoint: port, proto: transport_proto): bool
    {
    # Exact and wildcard rules are additive; an exact rule for another port
    # must not suppress a matching wildcard. Never change the recorded address.
    local wildcard: addr = is_v4_addr(host) ? 0.0.0.0 : [::];
    local is_local = host in local_hosts || host in 127.0.0.0/8 || host == [::1];
    return matches_rule(host, endpoint, proto) ||
           (is_local && matches_rule(wildcard, endpoint, proto));
    }

type Session: record {
    kind: string;
    remote_addr: addr;
    remote_port: count;
    server_addr: addr;
    server_port: count;
    protocol: string;
    bytes_sent: count;
    bytes_received: count;
    session_time: double;
};

global output: file;

event zeek_init() &priority=-1000
    {
    Log::remove_default_filter(Conn::LOG);
    output = open("/dev/stdout");
    set_buf(output, F);
    print output, "{\"kind\":\"ready\"}";
    }

event Conn::log_conn(c: Conn::Info)
    {
    if ( c$proto != tcp && c$proto != udp )
        return;
    local orig_server = is_server(c$id$orig_h, c$id$orig_p, c$proto);
    local resp_server = is_server(c$id$resp_h, c$id$resp_p, c$proto);
    if ( orig_server == resp_server )
        return;
    local s: Session = [
        $kind="session",
        $remote_addr=orig_server ? c$id$resp_h : c$id$orig_h,
        $remote_port=port_to_count(orig_server ? c$id$resp_p : c$id$orig_p),
        $server_addr=orig_server ? c$id$orig_h : c$id$resp_h,
        $server_port=port_to_count(orig_server ? c$id$orig_p : c$id$resp_p),
        $protocol=c$proto == tcp ? "TCP" : "UDP",
        $bytes_sent=orig_server ? c$orig_ip_bytes : c$resp_ip_bytes,
        $bytes_received=orig_server ? c$resp_ip_bytes : c$orig_ip_bytes,
        $session_time=c?$duration ? interval_to_double(c$duration) : 0.0
    ];
    print output, to_json(s);
    }
