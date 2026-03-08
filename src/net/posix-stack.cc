/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 */


#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <list>
#include <random>
#include <variant>
#include <coroutine>

#include <unistd.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <netinet/tcp.h>
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <seastar/util/assert.hh>

#include <seastar/core/loop.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/timer.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/byteorder.hh>
#include <seastar/net/posix-stack.hh>
#include <seastar/net/net.hh>
#include <seastar/net/packet.hh>
#include <seastar/net/api.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/util/std-compat.hh>
#include <seastar/util/defer.hh>
#include <seastar/util/later.hh>

namespace std {

template <>
struct hash<seastar::net::posix_ap_server_socket_impl::protocol_and_socket_address> {
    size_t operator()(const seastar::net::posix_ap_server_socket_impl::protocol_and_socket_address& t_sa) const {
        auto h1 = std::hash<int>()(std::get<0>(t_sa));
        auto h2 = std::hash<seastar::net::socket_address>()(std::get<1>(t_sa));
        return h1 ^ h2;
    }
};

}


namespace {

// reinterpret_cast<foo*>() on a pointer that the compiler knows points to an
// object with a different type is disliked by the compiler as it violates
// strict aliasing rules. This safe version does the same thing but keeps the
// compiler happy.
template <typename T>
T
copy_reinterpret_cast(const void* ptr) {
    T tmp;
    std::memcpy(&tmp, ptr, sizeof(T));
    return tmp;
}

thread_local std::array<uint64_t, seastar::max_scheduling_groups()> bytes_sent = {};
thread_local std::array<uint64_t, seastar::max_scheduling_groups()> bytes_received = {};

}

namespace seastar {

namespace internal {

std::pair<size_t, deleter> wrapped_iovecs::populate(std::span<temporary_buffer<char>> bufs) {
    size_t total = 0;
    deleter del;

    if (!v.empty()) {
        on_internal_error(seastar_logger, "wrapped_iovecs are re-populated live");
    }

    v.reserve(bufs.size());
    for (auto&& buf : bufs) {
        auto b = std::move(buf);
        total += b.size();
        v.push_back({ .iov_base = b.get_write(), .iov_len = b.size() });
        deleter d = b.release();
        d.append(std::move(del));
        del = std::move(d);
    }

    return std::make_pair(total, make_deleter(std::move(del), [this] { v.clear(); }));
}

}

namespace net {

using namespace seastar;

class posix_connected_socket_operations {
public:
    virtual ~posix_connected_socket_operations() = default;
    virtual void set_nodelay(file_desc& fd, bool nodelay) const = 0;
    virtual bool get_nodelay(file_desc& fd) const = 0;
    virtual void set_keepalive(file_desc& _fd, bool keepalive) const = 0;
    virtual bool get_keepalive(file_desc& _fd) const = 0;
    virtual void set_keepalive_parameters(file_desc& _fd, const keepalive_params& params) const = 0;
    virtual keepalive_params get_keepalive_parameters(file_desc& _fd) const = 0;
    virtual void set_sockopt(file_desc& _fd, int level, int optname, const void* data, size_t len) const {
        _fd.setsockopt(level, optname, data, socklen_t(len));
    }
    virtual int get_sockopt(file_desc& _fd, int level, int optname, void* data, size_t len) const {
        return _fd.getsockopt(level, optname, reinterpret_cast<char*>(data), socklen_t(len));
    }
    virtual socket_address local_address(file_desc& _fd) const {
        return _fd.get_address();
    }
    virtual socket_address remote_address(file_desc& _fd) const {
        try {
            return _fd.get_remote_address();
        } catch (const std::system_error& e) {
            if (e.code().value() != ENOTCONN) {
                throw;
            }
            return socket_address();
        }
    }
};

thread_local posix_ap_server_socket_impl::port_map_t posix_ap_server_socket_impl::ports{};
thread_local posix_ap_server_socket_impl::sockets_map_t posix_ap_server_socket_impl::sockets{};
thread_local posix_ap_server_socket_impl::conn_map_t posix_ap_server_socket_impl::conn_q{};

class posix_tcp_connected_socket_operations : public posix_connected_socket_operations {
public:
    virtual void set_nodelay(file_desc& _fd, bool nodelay) const override {
        _fd.setsockopt(IPPROTO_TCP, TCP_NODELAY, int(nodelay));
    }
    virtual bool get_nodelay(file_desc& _fd) const override {
        return _fd.getsockopt<int>(IPPROTO_TCP, TCP_NODELAY);
    }
    virtual void set_keepalive(file_desc& _fd, bool keepalive) const override {
        _fd.setsockopt(SOL_SOCKET, SO_KEEPALIVE, int(keepalive));
    }
    virtual bool get_keepalive(file_desc& _fd) const override {
        return _fd.getsockopt<int>(SOL_SOCKET, SO_KEEPALIVE);
    }
    virtual void set_keepalive_parameters(file_desc& _fd, const keepalive_params& params) const override {
        const tcp_keepalive_params& pms = std::get<tcp_keepalive_params>(params);
        _fd.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, pms.count);
        _fd.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, int(pms.idle.count()));
        _fd.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, int(pms.interval.count()));
    }
    virtual keepalive_params get_keepalive_parameters(file_desc& _fd) const override {
        return tcp_keepalive_params {
            std::chrono::seconds(_fd.getsockopt<int>(IPPROTO_TCP, TCP_KEEPIDLE)),
            std::chrono::seconds(_fd.getsockopt<int>(IPPROTO_TCP, TCP_KEEPINTVL)),
            _fd.getsockopt<unsigned>(IPPROTO_TCP, TCP_KEEPCNT)
        };
    }
};

class posix_sctp_connected_socket_operations : public posix_connected_socket_operations {
public:
    virtual void set_nodelay(file_desc& _fd, bool nodelay) const override {
        _fd.setsockopt(SOL_SCTP, SCTP_NODELAY, int(nodelay));
    }
    virtual bool get_nodelay(file_desc& _fd) const override {
        return _fd.getsockopt<int>(SOL_SCTP, SCTP_NODELAY);
    }
    virtual void set_keepalive(file_desc& _fd, bool keepalive) const override {
        auto heartbeat = _fd.getsockopt<sctp_paddrparams>(SOL_SCTP, SCTP_PEER_ADDR_PARAMS);
        if (keepalive) {
            heartbeat.spp_flags |= SPP_HB_ENABLE;
        } else {
            heartbeat.spp_flags &= ~SPP_HB_ENABLE;
        }
        _fd.setsockopt(SOL_SCTP, SCTP_PEER_ADDR_PARAMS, heartbeat);
    }
    virtual bool get_keepalive(file_desc& _fd) const override {
        return _fd.getsockopt<sctp_paddrparams>(SOL_SCTP, SCTP_PEER_ADDR_PARAMS).spp_flags & SPP_HB_ENABLE;
    }
    virtual void set_keepalive_parameters(file_desc& _fd, const keepalive_params& kpms) const override {
        const sctp_keepalive_params& pms = std::get<sctp_keepalive_params>(kpms);
        auto params = _fd.getsockopt<sctp_paddrparams>(SOL_SCTP, SCTP_PEER_ADDR_PARAMS);
        params.spp_hbinterval = pms.interval.count() * 1000; // in milliseconds
        params.spp_pathmaxrxt = pms.count;
        _fd.setsockopt(SOL_SCTP, SCTP_PEER_ADDR_PARAMS, params);
    }
    virtual keepalive_params get_keepalive_parameters(file_desc& _fd) const override {
        auto params = _fd.getsockopt<sctp_paddrparams>(SOL_SCTP, SCTP_PEER_ADDR_PARAMS);
        return sctp_keepalive_params {
            std::chrono::seconds(params.spp_hbinterval/1000), // in seconds
            params.spp_pathmaxrxt
        };
    }
};

class posix_unix_stream_connected_socket_operations : public posix_connected_socket_operations {
public:
    virtual void set_nodelay(file_desc& fd, bool nodelay) const override {
        SEASTAR_ASSERT(nodelay); // make sure nobody actually tries to use this non-existing functionality
    }
    virtual bool get_nodelay(file_desc& fd) const override {
        return true;
    }
    virtual void set_keepalive(file_desc& fd, bool keepalive) const override {}
    virtual bool get_keepalive(file_desc& fd) const override {
        return false;
    }
    virtual void set_keepalive_parameters(file_desc& fd, const keepalive_params& p) const override {}
    virtual keepalive_params get_keepalive_parameters(file_desc& fd) const override {
        return keepalive_params{};
    }
};

static const posix_connected_socket_operations*
get_posix_connected_socket_ops(sa_family_t family, int protocol) {
    static posix_tcp_connected_socket_operations tcp_ops;
    static posix_sctp_connected_socket_operations sctp_ops;
    static posix_unix_stream_connected_socket_operations unix_ops;
    switch (family) {
    case AF_INET:
    case AF_INET6:
        switch (protocol) {
        case IPPROTO_TCP: return &tcp_ops;
        case IPPROTO_SCTP: return &sctp_ops;
        default: abort();
        }
    case AF_UNIX:
        return &unix_ops;
    default:
        abort();
    }
}

static void shutdown_socket_fd(pollable_fd& fd, int how) noexcept {
    try {
        // file_desc::shutdown ignores ENOTCONN. Other reasons for exception
        // EINVAL (wrong "how") -- impossible
        // ENOTSOCK (not a socket) -- incredible
        // EBADF (invalid file descriptor) -- irretrievable
        fd.shutdown(how);
    } catch (...) {
        on_internal_error(seastar_logger, seastar::format("socket shutdown({}, {}) failed: {}", fd.get_file_desc().fdinfo(), how, seastar::formattable(std::current_exception())));
    }
}

class posix_connected_socket_impl : public connected_socket_impl {
    pollable_fd _fd;
    const posix_connected_socket_operations* _ops;
    conntrack::handle _handle;
    std::pmr::polymorphic_allocator<char>* _allocator;
public:
    explicit posix_connected_socket_impl(sa_family_t family, int protocol, pollable_fd fd, std::pmr::polymorphic_allocator<char>* allocator=memory::malloc_allocator) :
        _fd(std::move(fd)), _ops(get_posix_connected_socket_ops(family, protocol)), _allocator(allocator) {}
    explicit posix_connected_socket_impl(sa_family_t family, int protocol, pollable_fd fd, conntrack::handle&& handle,
        std::pmr::polymorphic_allocator<char>* allocator=memory::malloc_allocator) : _fd(std::move(fd))
                , _ops(get_posix_connected_socket_ops(family, protocol)), _handle(std::move(handle)), _allocator(allocator) {}
public:
    virtual data_source source() override {
        return source(connected_socket_input_stream_config());
    }
    virtual data_source source(connected_socket_input_stream_config csisc) override {
        return data_source(std::make_unique<posix_data_source_impl>(_fd, csisc, _allocator));
    }
    virtual data_sink sink() override {
        return data_sink(std::make_unique< posix_data_sink_impl>(_fd));
    }
    virtual void shutdown_input() override {
        shutdown_socket_fd(_fd, SHUT_RD);
    }
    virtual void shutdown_output() override {
        shutdown_socket_fd(_fd, SHUT_WR);
    }
    virtual void set_nodelay(bool nodelay) override {
        return _ops->set_nodelay(_fd.get_file_desc(), nodelay);
    }
    virtual bool get_nodelay() const override {
        return _ops->get_nodelay(_fd.get_file_desc());
    }
    void set_keepalive(bool keepalive) override {
        return _ops->set_keepalive(_fd.get_file_desc(), keepalive);
    }
    bool get_keepalive() const override {
        return _ops->get_keepalive(_fd.get_file_desc());
    }
    void set_keepalive_parameters(const keepalive_params& p) override {
        return _ops->set_keepalive_parameters(_fd.get_file_desc(), p);
    }
    keepalive_params get_keepalive_parameters() const override {
        return _ops->get_keepalive_parameters(_fd.get_file_desc());
    }
    void set_sockopt(int level, int optname, const void* data, size_t len) override {
        return _ops->set_sockopt(_fd.get_file_desc(), level, optname, data, len);
    }
    int get_sockopt(int level, int optname, void* data, size_t len) const override {
        return _ops->get_sockopt(_fd.get_file_desc(), level, optname, data, len);
    }
    socket_address local_address() const noexcept override {
        return _ops->local_address(_fd.get_file_desc());
    }
    socket_address remote_address() const noexcept override {
        return _ops->remote_address(_fd.get_file_desc());
    }
    future<> wait_input_shutdown() override {
        return _fd.poll_rdhup();
    }

    friend class posix_server_socket_impl;
    friend class posix_ap_server_socket_impl;
    friend class posix_reuseport_server_socket_impl;
    friend class posix_network_stack;
    friend class posix_ap_network_stack;
    friend class posix_socket_impl;
};

// Like posix_connected_socket_impl, but overrides local_address() and remote_address()
// to return the addresses from the PROXY protocol v2 header.
class posix_proxied_connected_socket_impl final : public posix_connected_socket_impl {
    socket_address _proxy_local_addr;
    socket_address _proxy_remote_addr;
public:
    posix_proxied_connected_socket_impl(
            sa_family_t family,
            int protocol,
            pollable_fd fd,
            conntrack::handle&& handle,
            socket_address proxy_local_addr,
            socket_address proxy_remote_addr,
            std::pmr::polymorphic_allocator<char>* allocator = memory::malloc_allocator)
        : posix_connected_socket_impl(family, protocol, std::move(fd), std::move(handle), allocator)
        , _proxy_local_addr(proxy_local_addr)
        , _proxy_remote_addr(proxy_remote_addr) {
    }
    virtual socket_address local_address() const noexcept override {
        return _proxy_local_addr;
    }
    virtual socket_address remote_address() const noexcept override {
        return _proxy_remote_addr;
    }
};

static void resolve_outgoing_address(socket_address& a) {
    if (a.family() != AF_INET6
        || a.as_posix_sockaddr_in6().sin6_scope_id != inet_address::invalid_scope
        || !IN6_IS_ADDR_LINKLOCAL(&a.as_posix_sockaddr_in6().sin6_addr)
    ) {
        return;
    }

    FILE *f;

    if (!(f = fopen("/proc/net/ipv6_route", "r"))) {
        throw std::system_error(errno, std::system_category(), "resolve_address");
    }

    auto holder = std::unique_ptr<FILE, int(*)(FILE *)>(f, &::fclose);

    /**
      Here all configured IPv6 routes are shown in a special format. The example displays for loopback interface only. The meaning is shown below (see net/ipv6/route.c for more).

    # cat /proc/net/ipv6_route
    00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000001 00200200 lo
    +------------------------------+ ++ +------------------------------+ ++ +------------------------------+ +------+ +------+ +------+ +------+ ++
    |                                |  |                                |  |                                |        |        |        |        |
    1                                2  3                                4  5                                6        7        8        9        10

    1: IPv6 destination network displayed in 32 hexadecimal chars without colons as separator

    2: IPv6 destination prefix length in hexadecimal

    3: IPv6 source network displayed in 32 hexadecimal chars without colons as separator

    4: IPv6 source prefix length in hexadecimal

    5: IPv6 next hop displayed in 32 hexadecimal chars without colons as separator

    6: Metric in hexadecimal

    7: Reference counter

    8: Use counter

    9: Flags

    10: Device name

    */

    uint32_t prefix_len, src_prefix_len;
    unsigned long flags;
    char device[16];
    char dest_str[40];

    for (;;) {
        auto n = fscanf(f, "%4s%4s%4s%4s%4s%4s%4s%4s %02x "
                            "%*4s%*4s%*4s%*4s%*4s%*4s%*4s%*4s %02x "
                            "%*4s%*4s%*4s%*4s%*4s%*4s%*4s%*4s "
                            "%*08x %*08x %*08x %08lx %8s",
                            &dest_str[0], &dest_str[5], &dest_str[10], &dest_str[15],
                            &dest_str[20], &dest_str[25], &dest_str[30], &dest_str[35],
                            &prefix_len,
                            &src_prefix_len,
                            &flags, device);
        if (n != 12) {
            break;
        }

        if ((prefix_len > 128)  || (src_prefix_len != 0)
            || (flags & (RTF_POLICY | RTF_FLOW))
            || ((flags & RTF_REJECT) && prefix_len == 0) /* reject all */) {
            continue;
        }

        dest_str[4] = dest_str[9] = dest_str[14] = dest_str[19] = dest_str[24] = dest_str[29] = dest_str[34] = ':';
        dest_str[39] = '\0';

        struct in6_addr addr;
        if (inet_pton(AF_INET6, dest_str, &addr) < 0) {
            /* not an Ipv6 address */
            continue;
        }

        auto bytes = prefix_len / 8;
        auto bits = prefix_len % 8;

        auto& src = a.as_posix_sockaddr_in6().sin6_addr;

        if (bytes > 0 && memcmp(&src, &addr, bytes)) {
            continue;
        }
        if (bits > 0) {
            auto c1 = src.s6_addr[bytes];
            auto c2 = addr.s6_addr[bytes];
            auto mask = 0xffu << (8 - bits);
            if ((c1 & mask) != (c2 & mask)) {
                continue;
            }
        }

        // found the route.
        for (auto& nif : engine().net().network_interfaces()) {
            if (nif.name() == device || nif.display_name() == device) {
                a.as_posix_sockaddr_in6().sin6_scope_id = nif.index();
                return;
            }
        }
    }
}

class posix_socket_impl final : public socket_impl {
    pollable_fd _fd;
    std::pmr::polymorphic_allocator<char>* _allocator;
    bool _reuseaddr = false;
    const int _sock_flags;

    future<> find_port_and_connect(socket_address sa, socket_address local, transport proto = transport::TCP) {
        static thread_local std::default_random_engine random_engine{std::random_device{}()};
        static thread_local std::uniform_int_distribution<uint16_t> u(49152/this_smp_shard_count() + 1, 65535/this_smp_shard_count() - 1);
        // If no explicit local address, set to dest address family wildcard.
        if (local.is_unspecified()) {
            local = net::inet_address(sa.addr().in_family());
        }
        resolve_outgoing_address(sa);
        auto attempts = 0;
        auto requested_port = ntoh(local.as_posix_sockaddr_in().sin_port);
        do {
            _fd = file_desc::socket(sa.u.sa.sa_family, _sock_flags, int(proto));
            _fd.get_file_desc().setsockopt(SOL_SOCKET, SO_REUSEADDR, int(_reuseaddr));
            uint16_t port = attempts++ < 5 && requested_port == 0 && proto == transport::TCP ? u(random_engine) * this_smp_shard_count() + this_shard_id() : requested_port;
            local.as_posix_sockaddr_in().sin_port = hton(port);
            try {
                co_await internal::posix_connect(_fd, sa, local);
                break;
            } catch (std::system_error& err) {
                if (port != requested_port && (err.code().value() == EADDRINUSE || err.code().value() == EADDRNOTAVAIL)) {
                    continue;
                }
                throw;
            }
        } while (true);
    }

    /// an aux function to handle unix-domain-specific requests
    future<connected_socket> connect_unix_domain(socket_address sa, socket_address local) {
        // note that if the 'local' address was not set by the client, it was created as an undefined address
        if (local.is_unspecified()) {
            local = socket_address{unix_domain_addr{std::string{}}};
        }

        _fd = file_desc::socket(sa.u.sa.sa_family, _sock_flags, 0);
        co_await internal::posix_connect(_fd, sa, local);
        auto csi = std::make_unique<posix_connected_socket_impl>(AF_UNIX, 0, _fd, _allocator);
        co_return connected_socket(std::move(csi));
    }

public:
    posix_socket_impl(bool need_nonblock, std::pmr::polymorphic_allocator<char>* allocator=memory::malloc_allocator)
            : _allocator(allocator)
            , _sock_flags(SOCK_STREAM | SOCK_CLOEXEC | (need_nonblock ? SOCK_NONBLOCK : 0))
    {}

    virtual future<connected_socket> connect(socket_address sa, socket_address local, transport proto = transport::TCP) override {
        if (sa.is_af_unix()) {
            co_return co_await connect_unix_domain(sa, local);
        }
        co_await find_port_and_connect(sa, local, proto);
        co_return connected_socket(std::make_unique<posix_connected_socket_impl>(sa.family(), static_cast<int>(proto), _fd, _allocator));
    }

    void set_reuseaddr(bool reuseaddr) override {
        _reuseaddr = reuseaddr;
        if (_fd) {
            _fd.get_file_desc().setsockopt(SOL_SOCKET, SO_REUSEADDR, int(reuseaddr));
        }
    }

    bool get_reuseaddr() const override {
        if(_fd) {
            return _fd.get_file_desc().getsockopt<int>(SOL_SOCKET, SO_REUSEADDR);
        } else {
            return _reuseaddr;
        }
    }

    virtual void shutdown() override {
        if (_fd) {
            try {
                _fd.shutdown(SHUT_RDWR);
            } catch (std::system_error& e) {
                if (e.code().value() != ENOTCONN) {
                    throw;
                }
            }
        }
    }
};

static
unsigned
get_port_or_counter(const socket_address& sa) {
    static thread_local constinit unsigned counter = 0;
    switch (sa.family()) {
    case AF_INET:
        return ntoh(sa.as_posix_sockaddr_in().sin_port);
    case AF_INET6:
        return ntoh(sa.as_posix_sockaddr_in6().sin6_port);
    default:
        // AF_UNIX? Shouldn't happen but not worth raising an error for it
        return counter++;
    }
}

static
proxy_data
local_proxy_data(const pollable_fd& pfd) {
    auto& fd = pfd.get_file_desc();

    auto local_sa = fd.get_address();
    auto remote_sa = fd.get_remote_address();

    proxy_data header = {
        .remote_address = remote_sa,
        .local_address = local_sa,
    };

    return header;
}

// Read exactly `len` bytes from fd into buf, looping on partial reads.
// Returns false on EOF before all bytes are read.
template <typename OnRead>
static
future<bool>
read_exactly(pollable_fd& fd, char* buf, size_t len, OnRead on_read) {
    size_t total = 0;
    while (total < len) {
        auto n = co_await fd.read_some(buf + total, len - total);
        if (n == 0) {
            co_return false;
        }
        total += n;
        on_read(n);
    }
    co_return true;
}

static future<bool> read_exactly(pollable_fd& fd, char* buf, size_t len) {
    return read_exactly(fd, buf, len, [] (size_t) {});
}

static const char pp2_signature[12] = {
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
};

// Parse PP v2 version/command, family/protocol, and addresses from a 16-byte
// header and an address payload buffer.  Returns nullopt on invalid data.
static
std::optional<proxy_data>
parse_pp2_addresses(const char* header, const char* addr_buf, uint16_t addr_len,
                    const pollable_fd& fd) {
    uint8_t fam_proto = header[13];
    switch (header[12]) { // version and command
    case 0x20: // v2, LOCAL
        if (fam_proto != 0x00) { // UNSPEC
            return std::nullopt;
        }
        return local_proxy_data(fd);
    case 0x21: // v2, PROXY
        break;
    default:
        return std::nullopt;
    }

    auto fam = fam_proto >> 4;
    auto proto = fam_proto & 0x0F;

    // We could, in principle, support DGRAM here, but there's no
    // real need for it. Real-world proxies support proxying UDP as UDP.
    if (proto != 0x1) { // STREAM
        return std::nullopt;
    }

    proxy_data addr_data;

    switch (fam) {
    case 0x1: { // INET
        if (addr_len < 12) {
            return std::nullopt;
        }
        addr_data.remote_address = ipv4_addr(inet_address(copy_reinterpret_cast<in_addr>(addr_buf)), read_be<uint16_t>(addr_buf + 8));
        addr_data.local_address = ipv4_addr(inet_address(copy_reinterpret_cast<in_addr>(addr_buf + 4)), read_be<uint16_t>(addr_buf + 10));
        break;
    }
    case 0x2: { // INET6
        if (addr_len < 36) {
            return std::nullopt;
        }
        addr_data.remote_address = ipv6_addr(inet_address(copy_reinterpret_cast<in6_addr>(addr_buf)), read_be<uint16_t>(addr_buf + 32));
        addr_data.local_address = ipv6_addr(inet_address(copy_reinterpret_cast<in6_addr>(addr_buf + 16)), read_be<uint16_t>(addr_buf + 34));
        break;
    }
    default:
        return std::nullopt;
    }
    return addr_data;
}

// Parses proxy protocol v2 header; returns std::nullopt if no valid header is found.
template <typename OnRead>
static
future<std::optional<proxy_data>>
read_proxy_data(pollable_fd& fd, OnRead on_read) {
    constexpr size_t pp2_header_len = 16;
    char header_buf[pp2_header_len];
    if (!co_await read_exactly(fd, header_buf, pp2_header_len, on_read)) {
        co_return std::nullopt;
    }
    if (std::memcmp(header_buf, pp2_signature, sizeof(pp2_signature)) != 0) {
        co_return std::nullopt;
    }

    auto len = read_be<uint16_t>(header_buf + 14);

    char stack_buffer[36]; // Suitable for IPv6 without extra TLVs
    std::unique_ptr<char[]> heap_buffer;
    auto* buffer = stack_buffer;

    if (len > sizeof(stack_buffer)) {
        heap_buffer = std::make_unique<char[]>(len);
        buffer = heap_buffer.get();
    }

    if (!co_await read_exactly(fd, buffer, len, on_read)) {
        co_return std::nullopt;
    }

    co_return parse_pp2_addresses(header_buf, buffer, len, fd);
}

// Data source that yields prefix bytes before delegating to the underlying source.
// Used by unified port to prepend bytes consumed during protocol detection.
class prefixed_data_source_impl final : public data_source_impl {
    lw_shared_ptr<std::optional<char>> _prefix;
    data_source _underlying;
public:
    prefixed_data_source_impl(lw_shared_ptr<std::optional<char>> prefix, data_source underlying)
        : _prefix(std::move(prefix)), _underlying(std::move(underlying)) {}
    future<temporary_buffer<char>> get() override {
        if (*_prefix) {
            temporary_buffer<char> buffer(1);
            *buffer.get_write() = **_prefix;
            _prefix->reset();
            return make_ready_future<temporary_buffer<char>>(std::move(buffer));
        }
        return _underlying.get();
    }
    future<> close() override {
        return _underlying.close();
    }
};

// Connected socket that prepends a single prefix byte to the data stream.
// Used by unified port for legacy clients where the first byte was consumed during detection.
class prefixed_posix_connected_socket_impl final : public posix_connected_socket_impl {
    lw_shared_ptr<std::optional<char>> _prefix;
    std::optional<proxy_data> _proxy;
public:
    prefixed_posix_connected_socket_impl(
            sa_family_t family, int protocol, pollable_fd fd,
            conntrack::handle&& handle,
            std::optional<char> prefix,
            std::optional<proxy_data> proxy,
            std::pmr::polymorphic_allocator<char>* allocator = memory::malloc_allocator)
        : posix_connected_socket_impl(family, protocol, std::move(fd), std::move(handle), allocator)
        , _prefix(make_lw_shared<std::optional<char>>(prefix))
        , _proxy(std::move(proxy)) {}
    socket_address remote_address() const noexcept override {
        return _proxy ? _proxy->remote_address : posix_connected_socket_impl::remote_address();
    }
    socket_address local_address() const noexcept override {
        return _proxy ? _proxy->local_address : posix_connected_socket_impl::local_address();
    }
    data_source source() override {
        return source(connected_socket_input_stream_config());
    }
    data_source source(connected_socket_input_stream_config csisc) override {
        auto underlying = posix_connected_socket_impl::source(csisc);
        if (!*_prefix) {
            return underlying;
        }
        // Creating an unused input stream before TLS wrapping must not consume
        // the saved byte. Whichever source reads first replays it exactly once.
        return data_source(std::make_unique<prefixed_data_source_impl>(
            _prefix, std::move(underlying)));
    }
};

// Magic byte for the unified port shard selection header.
static constexpr char unified_port_shard_select_magic = '\xAA';

static
std::unique_ptr<connected_socket_impl>
make_maybe_proxied_connected_socket_impl(
        sa_family_t family,
        int protocol,
        pollable_fd fd,
        conntrack::handle&& handle,
        std::optional<proxy_data> addr_data_opt,
        std::pmr::polymorphic_allocator<char>* allocator = memory::malloc_allocator) {
    if (addr_data_opt) {
        return std::make_unique<posix_proxied_connected_socket_impl>(
            family,
            protocol,
            std::move(fd),
            std::move(handle),
            std::move(addr_data_opt->local_address),
            std::move(addr_data_opt->remote_address),
            allocator);
    } else {
        return std::make_unique<posix_connected_socket_impl>(
            family,
            protocol,
            std::move(fd),
            std::move(handle),
            allocator);
    }
}

static
std::unique_ptr<connected_socket_impl>
make_unified_port_connected_socket_impl(
        sa_family_t family,
        int protocol,
        pollable_fd fd,
        conntrack::handle&& handle,
        std::optional<proxy_data> addr_data_opt,
        std::optional<char> prefix,
        std::pmr::polymorphic_allocator<char>* allocator = memory::malloc_allocator) {
    if (prefix) {
        return std::make_unique<prefixed_posix_connected_socket_impl>(
            family, protocol, std::move(fd), std::move(handle),
            prefix, std::move(addr_data_opt), allocator);
    }
    return make_maybe_proxied_connected_socket_impl(
        family, protocol, std::move(fd), std::move(handle),
        std::move(addr_data_opt), allocator);
}

// Limit both work awaiting preface bytes and sockets awaiting application accept.
static constexpr size_t unified_port_max_pending = 128;
static constexpr size_t unified_port_max_completed = 128;
static constexpr auto unified_port_preface_timeout = std::chrono::seconds(5);

struct posix_server_socket_impl::unified_port_state {
    using completed_accept = std::variant<accept_result, std::exception_ptr>;

    socket_address _sa;
    int _protocol;
    pollable_fd _lfd;
    conntrack _conntrack;
    std::optional<unified_port_options> _unified_port;
    std::pmr::polymorphic_allocator<char>* _allocator;
    semaphore _slots{unified_port_max_pending};
    gate _detectors;
    std::list<pollable_fd> _pending;
    queue<completed_accept> _completed{unified_port_max_completed};
    bool _stopped = false;

    explicit unified_port_state(posix_server_socket_impl& listener)
        : _sa(listener._sa), _protocol(listener._protocol), _lfd(listener._lfd)
        , _conntrack(listener._conntrack), _unified_port(listener._unified_port)
        , _allocator(listener._allocator) {
    }

    static void cancel(pollable_fd& fd) noexcept {
        if (fd) {
            try {
                fd.shutdown(SHUT_RDWR, pollable_fd::shutdown_kernel_only::no);
            } catch (...) {
                // A disconnected peer needs no further cancellation.
            }
        }
    }

    void stop(std::exception_ptr ex = std::make_exception_ptr(std::system_error(ECONNABORTED, std::system_category()))) noexcept {
        if (std::exchange(_stopped, true)) {
            return;
        }
        _slots.broken(ex);
        _completed.abort(ex);
        try {
            _lfd.shutdown(SHUT_RD, pollable_fd::shutdown_kernel_only::no);
        } catch (...) {
        }
        for (auto& fd : _pending) {
            cancel(fd);
        }
    }

    future<> detect(std::list<pollable_fd>::iterator socket, socket_address sa);

    future<> run(lw_shared_ptr<unified_port_state> self) {
        // Keep all state alive until the acceptor and every independent detector
        // have drained, including when the server_socket has already been destroyed.
        try {
            while (!_stopped) {
                auto units = co_await get_units(_slots, 1);
                auto accepted = co_await coroutine::as_future(_lfd.accept());
                if (accepted.failed()) {
                    completed_accept error = accepted.get_exception();
                    // An OS accept error belongs to one accept() call. Keep the
                    // listener alive so its caller can recover and retry.
                    while (!_stopped && !_completed.push(std::move(error))) {
                        co_await _completed.not_full();
                    }
                    // Persistent immediate failures must let other work run.
                    co_await yield();
                    continue;
                }
                if (_stopped) {
                    break;
                }
                auto [fd, sa] = accepted.get();
                auto socket = _pending.emplace(_pending.end(), std::move(fd));
                (void)with_gate(_detectors, [this, socket, sa] {
                    return detect(socket, sa);
                }).handle_exception([] (std::exception_ptr ex) {
                    seastar_logger.debug("unified port: dropping connection after preface failure: {}", ex);
                }).finally([self, socket, units = std::move(units)] {
                    self->_pending.erase(socket);
                });
            }
        } catch (...) {
            stop(std::current_exception());
        }
        co_await _detectors.close();
    }
};

future<>
posix_server_socket_impl::unified_port_state::detect(std::list<pollable_fd>::iterator socket, socket_address sa) {
    auto& fd = *socket;
    // One deadline covers all reads, including PPv2 payload and a following shard
    // header. Shut down and drain the read rather than abandoning its buffer.
    timer<lowres_clock> deadline([&fd] { cancel(fd); });
    deadline.arm(lowres_clock::now() + unified_port_preface_timeout);
    std::optional<proxy_data> addr_data_opt;
    connection_metadata meta;
    meta.physical_peer = sa;
    std::optional<char> prefix;
    bool has_shard_selection = false;
    unsigned target_shard = 0;

    // Read first byte to detect protocol layer
    char first_byte;
    if (!co_await read_exactly(fd, &first_byte, 1) || _stopped) {
        seastar_logger.debug("unified port: EOF on first byte, dropping connection");
        co_return;
    }

    // 1. Proxy Protocol v2 auto-detection (first byte 0x0D)
    if (first_byte == 0x0D) {
        if (_unified_port->proxy_protocol == unified_port_options::proxy_protocol_mode::disabled
                || !_unified_port->trusted_proxy || !_unified_port->trusted_proxy(sa.addr())) {
            seastar_logger.debug("unified port: PROXY header from a disallowed peer, dropping connection");
            co_return;
        }
        // Might be PP v2. Read remaining 15 bytes of the 16-byte header.
        char full_header[16];
        full_header[0] = first_byte;
        if (!co_await read_exactly(fd, full_header + 1, sizeof(full_header) - 1)) {
            seastar_logger.debug("unified port: incomplete PP v2 header, dropping connection");
            co_return;
        }

        if (std::memcmp(full_header, pp2_signature, sizeof(pp2_signature)) != 0) {
            seastar_logger.debug("unified port: invalid PP v2 signature, dropping connection");
            co_return;
        }

        auto len = read_be<uint16_t>(full_header + 14);

        char stack_buffer[36];
        std::unique_ptr<char[]> heap_buffer;
        auto* buffer = stack_buffer;
        if (len > sizeof(stack_buffer)) {
            heap_buffer = std::make_unique<char[]>(len);
            buffer = heap_buffer.get();
        }

        if (!co_await read_exactly(fd, buffer, len)) {
            seastar_logger.debug("unified port: incomplete PP v2 address data, dropping connection");
            co_return;
        }

        addr_data_opt = parse_pp2_addresses(full_header, buffer, len, fd);
        if (!addr_data_opt) {
            seastar_logger.debug("unified port: unsupported PP v2 address family or protocol, dropping connection");
            co_return;
        }
        sa = addr_data_opt->remote_address;

        // Read next byte for further detection
        if (!co_await read_exactly(fd, &first_byte, 1)) {
            seastar_logger.debug("unified port: EOF after PP v2 header, dropping connection");
            co_return;
        }
    } else if (_unified_port->proxy_protocol == unified_port_options::proxy_protocol_mode::required) {
        seastar_logger.debug("unified port: required PROXY header missing, dropping connection");
        co_return;
    }

    // 2. Shard selection header auto-detection (magic 0xAA)
    if (first_byte == unified_port_shard_select_magic) {
        char hdr[3]; // remaining 3 bytes of 4-byte header
        if (!co_await read_exactly(fd, hdr, 3)) {
            seastar_logger.debug("unified port: incomplete shard selection header, dropping connection");
            co_return;
        }

        uint8_t flags = static_cast<uint8_t>(hdr[0]);
        if (flags & ~uint8_t(0x01)) {
            seastar_logger.debug("unified port: reserved shard header flags, dropping connection");
            co_return;
        }
        meta.is_tls = (flags & 0x01) != 0;
        uint16_t shard_id = (static_cast<uint16_t>(static_cast<uint8_t>(hdr[1])) << 8)
                          | static_cast<uint8_t>(hdr[2]);
        target_shard = shard_id % this_smp_shard_count();
        has_shard_selection = true;
        // All header bytes consumed, fd stream starts with TLS or CQL data
    } else {
        // 3. Legacy client: first_byte is TLS (0x16) or CQL version (0x03+)
        meta.is_tls = (static_cast<uint8_t>(first_byte) == 0x16);
        // Save consumed byte as prefix to prepend to the data stream
        prefix = first_byte;
    }

    if ((meta.is_tls && _unified_port->encryption == unified_port_options::encryption_mode::plain_only)
            || (!meta.is_tls && _unified_port->encryption == unified_port_options::encryption_mode::tls_only)) {
        seastar_logger.debug("unified port: transport rejected by encryption policy");
        co_return;
    }

    if (!deadline.cancel() || _stopped) {
        co_return;
    }

    // Explicit shard headers take precedence over source-port routing.
    auto cth = has_shard_selection ? _conntrack.get_handle(target_shard)
        : _unified_port->source_port_routing ? _conntrack.get_handle(get_port_or_counter(sa) % this_smp_shard_count())
        : _conntrack.get_handle();

    auto cpu = cth.cpu();
    if (cpu == this_shard_id()) {
        auto csi = make_unified_port_connected_socket_impl(
            sa.family(), _protocol, std::move(fd), std::move(cth),
            std::move(addr_data_opt), prefix, _allocator);
        // A full serving queue drops the new connection instead of accumulating
        // unbounded completed sockets while the application is not accepting.
        _completed.push(accept_result{connected_socket(std::move(csi)), sa, meta});
    } else {
        co_await smp::submit_to(cpu, [protocol = _protocol, ssa = _sa,
                fd = fd.detach_file_desc(), sa, cth = std::move(cth),
                addr_data_opt = std::move(addr_data_opt), allocator = _allocator,
                meta, prefix] () mutable {
            posix_ap_server_socket_impl::move_connected_socket(
                protocol, ssa, pollable_fd(std::move(fd)), sa, std::move(cth),
                std::move(addr_data_opt), allocator, meta, prefix);
        });
    }
}

// The legacy accept loop is serial, but its pending I/O must outlive the
// listener when destruction cancels a fragmented PPv2 read.
struct posix_server_socket_impl::proxy_protocol_state {
    pollable_fd listener;
    pollable_fd pending;
    size_t bytes_read = 0;
    bool stopped = false;

    explicit proxy_protocol_state(pollable_fd fd) : listener(std::move(fd)) {}

    void stop() noexcept {
        if (std::exchange(stopped, true)) {
            return;
        }
        if (pending) {
            shutdown_socket_fd(pending, SHUT_RDWR);
        }
        try {
            listener.shutdown(SHUT_RD, pollable_fd::shutdown_kernel_only::no);
        } catch (...) {
        }
    }
};

size_t posix_server_socket_impl::proxy_protocol_bytes_read() const noexcept {
    return _proxy_state ? _proxy_state->bytes_read : 0;
}

posix_server_socket_impl::posix_server_socket_impl(int protocol, socket_address sa, pollable_fd lfd,
        server_socket::load_balancing_algorithm lba, shard_id fixed_cpu, bool proxy_protocol,
        std::optional<unified_port_options> unified_port, std::pmr::polymorphic_allocator<char>* allocator)
    : _sa(sa), _protocol(protocol), _lfd(std::move(lfd)), _lba(lba), _fixed_cpu(fixed_cpu)
    , _proxy_protocol(proxy_protocol), _unified_port(std::move(unified_port)), _allocator(allocator) {
    if (_proxy_protocol) {
        _proxy_state = make_lw_shared<proxy_protocol_state>(_lfd);
    }
}

posix_server_socket_impl::~posix_server_socket_impl() {
    if (_proxy_state) {
        _proxy_state->stop();
    }
    if (_unified_state) {
        _unified_state->stop();
    }
}

future<accept_result>
posix_server_socket_impl::accept_unified_port() {
    if (!_unified_state) {
        _unified_state = make_lw_shared<unified_port_state>(*this);
        (void)_unified_state->run(_unified_state);
    }
    auto state = _unified_state;
    auto completed = co_await state->_completed.pop_eventually();
    if (auto error = std::get_if<std::exception_ptr>(&completed)) {
        co_return coroutine::exception(*error);
    }
    co_return std::move(std::get<accept_result>(completed));
}

future<accept_result>
posix_server_socket_impl::accept() {
    if (_unified_port) {
        co_return co_await accept_unified_port();
    }
    auto proxy = _proxy_state;
    while (true) { // exited via co_return
        auto [fd, sa] = co_await _lfd.accept();
        // Destruction may have cancelled the wait. Use retained state before
        // touching any listener member after an asynchronous operation.
        if (proxy && proxy->stopped) {
            throw std::system_error(ECONNABORTED, std::system_category());
        }

        std::optional<proxy_data> addr_data_opt;
        if (_proxy_protocol) {
            // Preserve fragmented headers without letting a partial peer hold
            // serial admission or listener shutdown indefinitely.
            proxy->pending = fd;
            proxy->bytes_read = 0;
            auto clear_pending = defer([proxy] () noexcept { proxy->pending = {}; });
            timer<lowres_clock> deadline([proxy] { shutdown_socket_fd(proxy->pending, SHUT_RDWR); });
            deadline.arm(lowres_clock::now() + std::chrono::seconds(5));
            try {
                addr_data_opt = co_await read_proxy_data(fd, [proxy] (size_t bytes) { proxy->bytes_read += bytes; });
            } catch (const std::system_error&) {
                // Reset peers are dropped like incomplete or invalid headers.
            }
            if (proxy->stopped) {
                throw std::system_error(ECONNABORTED, std::system_category());
            }
            if (!deadline.cancel() || !addr_data_opt) {
                continue; // drop the connection
            }
            sa = addr_data_opt->remote_address;
        }

        auto cth = conntrack::handle();
        switch(_lba) {
        case server_socket::load_balancing_algorithm::connection_distribution:
            cth = _conntrack.get_handle();
            break;
        case server_socket::load_balancing_algorithm::port:
            cth = _conntrack.get_handle(get_port_or_counter(sa) % this_smp_shard_count());
            break;
        case server_socket::load_balancing_algorithm::fixed:
            cth = _conntrack.get_handle(_fixed_cpu);
            break;
        default: abort();
        }

        auto cpu = cth.cpu();
        if (cpu == this_shard_id()) {
            auto csi = make_maybe_proxied_connected_socket_impl(
                sa.family(),
                _protocol,
                std::move(fd),
                std::move(cth),
                std::move(addr_data_opt),
                _allocator);
            co_return accept_result{connected_socket(std::move(csi)), sa};
        } else {
            // Reading the proxy-protocol header may have left the socket in the poll set of this shard.
            // FIXME: future is discarded
            (void)smp::submit_to(cpu, [protocol = _protocol, ssa = _sa, fd = fd.detach_file_desc(), sa, cth = std::move(cth), addr_data_opt = std::move(addr_data_opt), allocator = _allocator] () mutable {
                posix_ap_server_socket_impl::move_connected_socket(protocol, ssa, pollable_fd(std::move(fd)), sa, std::move(cth), std::move(addr_data_opt), allocator);
            });
        }
    };
}

void
posix_server_socket_impl::abort_accept() {
    if (_proxy_state) {
        _proxy_state->stop();
        return;
    }
    if (_unified_state) {
        _unified_state->stop();
        return;
    }
    _lfd.shutdown(SHUT_RD, pollable_fd::shutdown_kernel_only::no);
}

socket_address posix_server_socket_impl::local_address() const {
    return _lfd.get_file_desc().get_address();
}

posix_ap_server_socket_impl::posix_ap_server_socket_impl(int protocol, socket_address sa, std::pmr::polymorphic_allocator<char>* allocator, bool unified_port)
        : _protocol(protocol), _sa(sa), _allocator(allocator), _unified_port(unified_port)
{
    auto it = ports.emplace(std::make_tuple(_protocol, _sa), port_state{unified_port});
    if (!it.second) {
        throw std::system_error(EADDRINUSE, std::system_category());
    }
}

posix_ap_server_socket_impl::~posix_ap_server_socket_impl() {
    if (_unified_port) {
        abort_accept();
    }
    auto t_sa = std::make_tuple(_protocol, _sa);
    conn_q.erase(t_sa);
    ports.erase(t_sa);
}

future<accept_result> posix_ap_server_socket_impl::accept() {
    auto t_sa = std::make_tuple(_protocol, _sa);
    if (_unified_port && ports.at(t_sa).aborted) {
        return make_exception_future<accept_result>(std::system_error(ECONNABORTED, std::system_category()));
    }
    auto conni = conn_q.find(t_sa);
    if (conni != conn_q.end()) {
        connection c = std::move(conni->second);
        conn_q.erase(conni);
        try {
            auto csi = make_unified_port_connected_socket_impl(
                _sa.family(), _protocol, std::move(c.fd),
                std::move(c.connection_tracking_handle),
                std::move(c.proxy_protocol_header_opt), c.prefix, _allocator);
            return make_ready_future<accept_result>(accept_result{connected_socket(std::move(csi)), std::move(c.addr), c.metadata});
        } catch (...) {
            return make_exception_future<accept_result>(std::current_exception());
        }
    } else {
        try {
            auto i = sockets.emplace(std::piecewise_construct, std::make_tuple(t_sa), std::make_tuple());
            SEASTAR_ASSERT(i.second);
            return i.first->second.get_future();
        } catch (...) {
            return make_exception_future<accept_result>(std::current_exception());
        }
    }
}

void
posix_ap_server_socket_impl::abort_accept() {
    auto t_sa = std::make_tuple(_protocol, _sa);
    if (_unified_port) {
        ports.at(t_sa).aborted = true;
    }
    conn_q.erase(t_sa);
    auto i = sockets.find(t_sa);
    if (i != sockets.end()) {
        i->second.set_exception(std::system_error(ECONNABORTED, std::system_category()));
        sockets.erase(i);
    }
}

future<accept_result>
posix_reuseport_server_socket_impl::accept() {
    auto [fd, sa] = co_await _lfd.accept();
    auto csi = std::make_unique<posix_connected_socket_impl>(sa.family(), _protocol, std::move(fd), _allocator);
    co_return accept_result{connected_socket(std::move(csi)), sa};
}

void
posix_reuseport_server_socket_impl::abort_accept() {
    _lfd.shutdown(SHUT_RD, pollable_fd::shutdown_kernel_only::no);
}

socket_address posix_reuseport_server_socket_impl::local_address() const {
    return _lfd.get_file_desc().get_address();
}

void
posix_ap_server_socket_impl::move_connected_socket(int protocol, socket_address sa, pollable_fd fd, socket_address addr,
        conntrack::handle cth, std::optional<proxy_data> addr_data_opt, std::pmr::polymorphic_allocator<char>* allocator,
        connection_metadata meta, std::optional<char> prefix) {
    auto t_sa = std::make_tuple(protocol, sa);
    auto i = sockets.find(t_sa);
    if (i != sockets.end()) {
        try {
            auto csi = make_unified_port_connected_socket_impl(
                sa.family(), protocol, std::move(fd), std::move(cth),
                std::move(addr_data_opt), prefix, allocator);
            i->second.set_value(accept_result{connected_socket(std::move(csi)), std::move(addr), meta});
        } catch (...) {
            i->second.set_exception(std::current_exception());
        }
        sockets.erase(i);
    } else if (auto port = ports.find(t_sa); port != ports.end() && !port->second.aborted
            && (!port->second.unified || conn_q.count(t_sa) < unified_port_max_completed)) {
        conn_q.emplace(std::piecewise_construct, std::make_tuple(t_sa),
                std::make_tuple(std::move(fd), std::move(addr), std::move(cth), std::move(addr_data_opt), meta, prefix));
    } else {
        // The listener stopped or its completion queue is full; drop the socket.
        fd.close();
    }
}

future<temporary_buffer<char>>
posix_data_source_impl::get() {
    return _fd.recv_some(static_cast<internal::buffer_allocator*>(this)).then([this] (temporary_buffer<char> b) {
        if (b.size() >= _config.buffer_size) {
            _config.buffer_size *= 2;
            _config.buffer_size = std::min(_config.buffer_size, _config.max_buffer_size);
        } else if (b.size() <= _config.buffer_size / 4) {
            _config.buffer_size /= 2;
            _config.buffer_size = std::max(_config.buffer_size, _config.min_buffer_size);
        }
        auto sg_id = internal::scheduling_group_index(current_scheduling_group());
        bytes_received[sg_id] += b.size();
        return b;
    });
}

temporary_buffer<char>
posix_data_source_impl::allocate_buffer() {
    return make_temporary_buffer<char>(_buffer_allocator, _config.buffer_size);
}

future<> posix_data_source_impl::close() {
    _fd.shutdown(SHUT_RD);
    return make_ready_future<>();
}

#if SEASTAR_API_LEVEL >= 9
future<> posix_data_sink_impl::put(std::span<temporary_buffer<char>> bufs) {
    auto [ total, del ] = _vecs.populate(bufs);
    auto sg_id = internal::scheduling_group_index(current_scheduling_group());
    bytes_sent[sg_id] += total;
    return _fd.send_all(_vecs.v).finally([del = std::move(del)] {} );
}
#else
future<>
posix_data_sink_impl::put(temporary_buffer<char> buf) {
    auto sg_id = internal::scheduling_group_index(current_scheduling_group());
    bytes_sent[sg_id] += buf.size();
    return _fd.write_all(buf.get(), buf.size()).then([d = buf.release()] {});
}

future<>
posix_data_sink_impl::put(packet p) {
    SEASTAR_ASSERT(!_p);
    _p = std::move(p);
    auto sg_id = internal::scheduling_group_index(current_scheduling_group());
    bytes_sent[sg_id] += _p.len();
    return _fd.write_all(_p).finally([this] { _p.reset(); });
}
#endif

future<>
posix_data_sink_impl::close() {
    _fd.shutdown(SHUT_WR);
    return make_ready_future<>();
}

void posix_data_sink_impl::on_batch_flush_error() noexcept {
    shutdown_socket_fd(_fd, SHUT_RD);
}

posix_network_stack::posix_network_stack(const program_options::option_group& opts, std::pmr::polymorphic_allocator<char>* allocator)
        : _reuseport(engine().posix_reuseport_available())
        , _sock_need_nonblock(engine().posix_sock_need_nonblock())
        , _allocator(allocator)
{
}

server_socket
posix_network_stack::listen(socket_address sa, listen_options opt) {
    using server_socket = seastar::server_socket;
    if (opt.unified_port && opt.proxy_protocol) {
        throw std::invalid_argument("unified_port and proxy_protocol cannot both be set");
    }
    // allow unspecified bind address -> default to ipv4 wildcard
    if (sa.is_unspecified()) {
        sa = inet_address(inet_address::family::INET);
    }
    if (sa.is_af_unix()) {
        return server_socket(std::make_unique<posix_server_socket_impl>(0, sa, internal::posix_listen(sa, opt),
                opt.lba, opt.fixed_cpu, opt.proxy_protocol, opt.unified_port, _allocator));
    }
    auto protocol = static_cast<int>(opt.proto);
    return _reuseport && !opt.unified_port ?
        server_socket(std::make_unique<posix_reuseport_server_socket_impl>(protocol, sa, internal::posix_listen(sa, opt), _allocator))
        :
        server_socket(std::make_unique<posix_server_socket_impl>(protocol, sa, internal::posix_listen(sa, opt),
                opt.lba, opt.fixed_cpu, opt.proxy_protocol, opt.unified_port, _allocator));
}

::seastar::socket posix_network_stack::socket() {
    return ::seastar::socket(std::make_unique<posix_socket_impl>(_sock_need_nonblock, _allocator));
}

posix_ap_network_stack::posix_ap_network_stack(const program_options::option_group& opts, std::pmr::polymorphic_allocator<char>* allocator)
        : posix_network_stack(opts, allocator)
{
}

server_socket
posix_ap_network_stack::listen(socket_address sa, listen_options opt) {
    using server_socket = seastar::server_socket;
    if (opt.unified_port && opt.proxy_protocol) {
        throw std::invalid_argument("unified_port and proxy_protocol cannot both be set");
    }
    // allow unspecified bind address -> default to ipv4 wildcard
    if (sa.is_unspecified()) {
        sa = inet_address(inet_address::family::INET);
    }
    if (sa.is_af_unix()) {
        return server_socket(std::make_unique<posix_ap_server_socket_impl>(0, sa, _allocator));
    }
    auto protocol = static_cast<int>(opt.proto);
    return posix_network_stack::_reuseport && !opt.unified_port ?
        server_socket(std::make_unique<posix_reuseport_server_socket_impl>(protocol, sa, internal::posix_listen(sa, opt), _allocator))
        :
        server_socket(std::make_unique<posix_ap_server_socket_impl>(protocol, sa, _allocator, opt.unified_port.has_value()));
}

class posix_datagram_channel : public datagram_channel_impl {
private:
    static constexpr int MAX_DATAGRAM_SIZE = 65507;
    struct recv_ctx {
        struct msghdr _hdr;
        struct iovec _iov;
        socket_address _src_addr;
        char* _buffer;
        alignas(struct cmsghdr) char _cmsg[std::max(CMSG_SPACE(sizeof(struct in_pktinfo)), CMSG_SPACE(sizeof(struct in6_pktinfo)))];

        recv_ctx(bool use_pktinfo) {
            memset(&_hdr, 0, sizeof(_hdr));
            _hdr.msg_iov = &_iov;
            _hdr.msg_iovlen = 1;
            _hdr.msg_name = &_src_addr.u.sa;
            if (use_pktinfo) {
                _hdr.msg_control = _cmsg;
            }
        }

        recv_ctx(const recv_ctx&) = delete;
        recv_ctx(recv_ctx&&) = delete;

        void prepare() {
            _buffer = new char[MAX_DATAGRAM_SIZE];
            _iov.iov_base = _buffer;
            _iov.iov_len = MAX_DATAGRAM_SIZE;
            // recvmsg() overwrites these
            _hdr.msg_namelen = sizeof(_src_addr.u.sas);
            _hdr.msg_controllen = _hdr.msg_control ? sizeof(_cmsg) : 0;
        }
    };
    struct send_ctx {
        struct msghdr _hdr;
        internal::wrapped_iovecs _vecs;
        socket_address _dst;

        send_ctx() {
            memset(&_hdr, 0, sizeof(_hdr));
            _hdr.msg_name = &_dst.u.sa;
            _hdr.msg_namelen = _dst.addr_length;
        }

        send_ctx(const send_ctx&) = delete;
        send_ctx(send_ctx&&) = delete;

        auto prepare(const socket_address& dst, std::span<temporary_buffer<char>> bufs) {
            _dst = dst;
            _hdr.msg_namelen = _dst.addr_length;
            auto ret = _vecs.populate(bufs);
            _hdr.msg_iov = _vecs.v.data();
            _hdr.msg_iovlen = _vecs.v.size();
            resolve_outgoing_address(_dst);
            return ret;
        }
    };

    static bool is_inet(sa_family_t family) {
        return family == AF_INET || family == AF_INET6;
    }

    static file_desc create_socket(sa_family_t family) {
        file_desc fd = file_desc::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

        if (is_inet(family)) {
            if (family == AF_INET6) {
                fd.setsockopt(IPPROTO_IPV6, IPV6_RECVPKTINFO, 1);
            } else {
                fd.setsockopt(SOL_IP, IP_PKTINFO, 1);
            }
            if (engine().posix_reuseport_available()) {
                fd.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1);
            }
        }

        return fd;
    }

    pollable_fd _fd;
    socket_address _address;
    recv_ctx _recv;
    send_ctx _send;
    bool _closed;
public:
    /// Creates a channel that is not bound to any socket address. The channel
    /// can be used to communicate with adressess that belong to the \param
    /// family.
    posix_datagram_channel(sa_family_t family)
        : _recv(is_inet(family)), _closed(false) {
        auto fd = create_socket(family);

        _address = fd.get_address();
        _fd = std::move(fd);
    }

    /// Creates a channel that is bound to the specified local address. It can be used to
    /// communicate with addresses that belong to the family of \param local.
    posix_datagram_channel(socket_address local)
        : _recv(is_inet(local.family())), _closed(false) {
        auto fd = create_socket(local.family());
        fd.bind(local.u.sa, local.addr_length);

        _address = fd.get_address();
        _fd = std::move(fd);
    }

    virtual ~posix_datagram_channel() { if (!_closed) close(); };
    virtual future<datagram> receive() override;
    virtual future<> send(const socket_address& dst, const char *msg) override;
    virtual future<> send(const socket_address& dst, std::span<temporary_buffer<char>> bufs) override;
    virtual void shutdown_input() override {
        _fd.shutdown(SHUT_RD, pollable_fd::shutdown_kernel_only::no);
    }
    virtual void shutdown_output() override {
        _fd.shutdown(SHUT_WR, pollable_fd::shutdown_kernel_only::no);
    }
    virtual void close() override {
        _closed = true;
        _fd = {};
    }
    virtual bool is_closed() const override { return _closed; }
    socket_address local_address() const override {
        SEASTAR_ASSERT(_address.u.sas.ss_family != AF_INET6 || (_address.addr_length > 20));
        return _address;
    }
};

future<> posix_datagram_channel::send(const socket_address& dst, const char *message) {
    auto len = strlen(message);
    auto a = dst;
    resolve_outgoing_address(a);
    auto sg_id = internal::scheduling_group_index(current_scheduling_group());
    bytes_sent[sg_id] += len;
    return _fd.sendto(a, message, len)
            .then([len] (size_t size) { SEASTAR_ASSERT(size == len); });
}

future<> posix_datagram_channel::send(const socket_address& dst, std::span<temporary_buffer<char>> bufs) {
    auto sg_id = internal::scheduling_group_index(current_scheduling_group());
    auto [ len, del ] = _send.prepare(dst, bufs);
    bytes_sent[sg_id] += len;
    return _fd.sendmsg(&_send._hdr)
            .then([len, del = std::move(del) ] (size_t size) { SEASTAR_ASSERT(size == len); });
}

datagram_channel
posix_network_stack::make_unbound_datagram_channel(sa_family_t family) {
    return datagram_channel(std::make_unique<posix_datagram_channel>(family));
}

datagram_channel
posix_network_stack::make_bound_datagram_channel(const socket_address& local) {
    return datagram_channel(std::make_unique<posix_datagram_channel>(local));
}

bool
posix_network_stack::supports_ipv6() const {
    static bool has_ipv6 = [] {
        try {
            posix_datagram_channel c(ipv6_addr{"::1"});
            c.close();
            return true;
        } catch (...) {}
        return false;
    }();

    return has_ipv6;
}

class posix_datagram : public datagram_impl {
private:
    socket_address _src;
    socket_address _dst;
    temporary_buffer<char> _buf;
public:
    posix_datagram(const socket_address& src, const socket_address& dst, temporary_buffer<char> b) : _src(src), _dst(dst), _buf(std::move(b)) {}
    virtual socket_address get_src() override { return _src; }
    virtual socket_address get_dst() override { return _dst; }
    virtual uint16_t get_dst_port() override {
        if (_dst.family() != AF_INET && _dst.family() != AF_INET6) {
            throw std::runtime_error(format("get_dst_port() called on non-IP address: {}", _dst));
        }
        return _dst.port();
    }
    virtual std::span<temporary_buffer<char>> get_buffers() override { return std::span(&_buf, 1); }
};

future<datagram>
posix_datagram_channel::receive() {
    _recv.prepare();
    return _fd.recvmsg(&_recv._hdr).then([this] (size_t size) {
        if (_recv._hdr.msg_namelen < sizeof(sa_family_t)) {
            // an unbound AF_UNIX sender has no name and recvmsg() leaves msg_name untouched
            memset(&_recv._src_addr.u, 0, sizeof(_recv._src_addr.u));
            _recv._src_addr.u.sa.sa_family = _address.family();
            _recv._src_addr.addr_length = sizeof(sa_family_t);
        } else {
            _recv._src_addr.addr_length = _recv._hdr.msg_namelen;
        }
        std::optional<socket_address> dst;
        for (auto* cmsg = CMSG_FIRSTHDR(&_recv._hdr); cmsg != nullptr; cmsg = CMSG_NXTHDR(&_recv._hdr, cmsg)) {
            // a truncated cmsg keeps its header but not all its data
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO && cmsg->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo))) {
                dst = ipv4_addr(copy_reinterpret_cast<in_pktinfo>(CMSG_DATA(cmsg)).ipi_addr, _address.port());
                break;
            } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO && cmsg->cmsg_len >= CMSG_LEN(sizeof(in6_pktinfo))) {
                dst = ipv6_addr(copy_reinterpret_cast<in6_pktinfo>(CMSG_DATA(cmsg)).ipi6_addr, _address.port());
                break;
            }
        }
        auto sg_id = internal::scheduling_group_index(current_scheduling_group());
        bytes_received[sg_id] += size;
        return make_ready_future<datagram>(datagram(std::make_unique<posix_datagram>(
            _recv._src_addr, dst ? *dst : _address, temporary_buffer<char>(_recv._buffer, size, make_deleter([buf = _recv._buffer] { delete[] buf; })))));
    }).handle_exception([p = _recv._buffer](auto ep) {
        delete[] p;
        return make_exception_future<datagram>(std::move(ep));
    });
}

network_stack_entry register_posix_stack() {
    return network_stack_entry{
        "posix", std::make_unique<program_options::option_group>(nullptr, "Posix"),
        [](const program_options::option_group& ops) {
            return smp::main_thread() ? posix_network_stack::create(ops)
                                      : posix_ap_network_stack::create(ops);
        },
        true};
}

// nw interface stuff

std::vector<network_interface> posix_network_stack::network_interfaces() {
    class posix_network_interface_impl final : public network_interface_impl {
    public:
        uint32_t _index = 0, _mtu = 0;
        sstring _name, _display_name;
        std::vector<net::inet_address> _addresses;
        std::vector<uint8_t> _hardware_address;
        bool _loopback = false, _virtual = false, _up = false;

        uint32_t index() const override {
            return _index;
        }
        uint32_t mtu() const override {
            return _mtu;
        }
        const sstring& name() const override {
            return _name;
        }
        const sstring& display_name() const override {
            return _display_name.empty() ? name() : _display_name;
        }
        const std::vector<net::inet_address>& addresses() const override {
            return _addresses;
        }
        const std::vector<uint8_t> hardware_address() const override {
            return _hardware_address;
        }
        bool is_loopback() const override {
            return _loopback;
        }
        bool is_virtual() const override {
            return _virtual;
        }
        bool is_up() const override {
            // TODO: should be checked on query?
            return _up;
        }
        bool supports_ipv6() const override {
            // TODO: this is not 100% correct.
            return std::any_of(_addresses.begin(), _addresses.end(), std::mem_fn(&inet_address::is_ipv6));
        }
    };

    // For now, keep an immutable set of interfaces created on start, shared across
    // shards
    static const std::vector<posix_network_interface_impl> global_interfaces = [] {
        auto fd = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        throw_system_error_on(fd < 0, "could not open netlink socket");

        std::unique_ptr<int, void(*)(int*)> fd_guard(&fd, [](int* p) { ::close(*p); });

        auto pid = ::getpid();

        sockaddr_nl local = {
          .nl_family = AF_NETLINK,
          .nl_pid = static_cast<unsigned int>(pid),
          .nl_groups = RTMGRP_IPV6_IFADDR|RTMGRP_IPV4_IFADDR,
        };

        throw_system_error_on(bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0, "could not bind netlink socket");

        /* RTNL socket is ready for use, prepare and send requests */

        std::vector<posix_network_interface_impl> res;

        for (auto msg : { RTM_GETLINK, RTM_GETADDR}) {
            struct nl_req {
                nlmsghdr hdr;
                union {
                    rtgenmsg gen;
                    ifaddrmsg addr;
                };
            } req = {};

            req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
            req.hdr.nlmsg_type = msg;
            req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
            req.hdr.nlmsg_seq = 1;
            req.hdr.nlmsg_pid = pid;

            if (msg == RTM_GETLINK) {
                req.gen.rtgen_family = AF_PACKET; /*  no preferred AF, we will get *all* interfaces */
            } else {
                req.addr.ifa_family = AF_UNSPEC;
            }

            sockaddr_nl kernel = {
              .nl_family = AF_NETLINK, /* fill-in kernel address (destination of our message) */
            };
            iovec io = {
              .iov_base = &req,
              .iov_len = req.hdr.nlmsg_len,
            };
            msghdr rtnl_msg = {
              .msg_name = &kernel,
              .msg_namelen = sizeof(kernel),
              .msg_iov = &io,
              .msg_iovlen = 1,
            };

            throw_system_error_on(::sendmsg(fd, (struct msghdr *) &rtnl_msg, 0) < 0, "could not send netlink request");
            /* parse reply */

            constexpr size_t reply_buffer_size = 8192;
            char reply[reply_buffer_size];

            bool done = false;

            while (!done) {
                iovec io_reply = {
                  .iov_base = reply,
                  .iov_len = reply_buffer_size,
                };
                msghdr rtnl_reply = {
                  .msg_name = &kernel,
                  .msg_namelen = sizeof(kernel),
                  .msg_iov = &io_reply,
                  .msg_iovlen = 1,
                };

                auto len = ::recvmsg(fd, &rtnl_reply, 0); /* read as much data as fits in the receive buffer */
                if (len <= 0) {
                    return res;
                }

                for (auto* msg_ptr = (struct nlmsghdr *) reply; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
                    switch(msg_ptr->nlmsg_type) {
                    case NLMSG_DONE: // that is all
                        done = true;
                        break;
                    case RTM_NEWLINK:
                    {
                        auto* iface = reinterpret_cast<const ifinfomsg*>(NLMSG_DATA(msg_ptr));
                        auto ilen = msg_ptr->nlmsg_len - NLMSG_LENGTH(sizeof(ifinfomsg));

                        // todo: filter any non-network interfaces (family)

                        posix_network_interface_impl nwif;

                        nwif._index = iface->ifi_index;
                        nwif._loopback = (iface->ifi_flags & IFF_LOOPBACK) != 0;
                        nwif._up = (iface->ifi_flags & IFF_UP) != 0;
    #if defined(IFF_802_1Q_VLAN) && defined(IFF_EBRIDGE) && defined(IFF_SLAVE_INACTIVE)
                        nwif._virtual = (iface->ifi_flags & (IFF_802_1Q_VLAN|IFF_EBRIDGE|IFF_SLAVE_INACTIVE)) != 0;
    #endif
                        for (auto* attribute = IFLA_RTA(iface); RTA_OK(attribute, ilen); attribute = RTA_NEXT(attribute, ilen)) {
                            switch(attribute->rta_type) {
                            case IFLA_IFNAME:
                                nwif._name = reinterpret_cast<const char *>(RTA_DATA(attribute));
                                break;
                            case IFLA_MTU:
                                nwif._mtu = *reinterpret_cast<const uint32_t *>(RTA_DATA(attribute));
                                break;
                            case IFLA_ADDRESS:
                                nwif._hardware_address.assign(reinterpret_cast<const uint8_t *>(RTA_DATA(attribute)), reinterpret_cast<const uint8_t *>(RTA_DATA(attribute)) + RTA_PAYLOAD(attribute));
                                break;
                            default:
                                break;
                            }
                        }

                        res.emplace_back(std::move(nwif));

                        break;
                    }
                    case RTM_NEWADDR:
                    {
                        auto* addr = reinterpret_cast<const ifaddrmsg*>(NLMSG_DATA(msg_ptr));
                        auto ilen = msg_ptr->nlmsg_len - NLMSG_LENGTH(sizeof(ifaddrmsg));

                        for (auto& nwif : res) {
                            if (nwif._index == addr->ifa_index) {
                                for (auto* attribute = IFA_RTA(addr); RTA_OK(attribute, ilen); attribute = RTA_NEXT(attribute, ilen)) {
                                    std::optional<inet_address> ia;

                                    switch(attribute->rta_type) {
                                    case IFA_LOCAL:
                                    case IFA_ADDRESS: // ipv6 addresses are reported only as "ADDRESS"

                                        if (RTA_PAYLOAD(attribute) == sizeof(::in_addr)) {
                                            ia.emplace(*reinterpret_cast<const ::in_addr *>(RTA_DATA(attribute)));
                                        } else if (RTA_PAYLOAD(attribute) == sizeof(::in6_addr)) {
                                            ia.emplace(*reinterpret_cast<const ::in6_addr *>(RTA_DATA(attribute)), nwif.index());
                                        }

                                        if (ia && std::find(nwif._addresses.begin(), nwif._addresses.end(), *ia) == nwif._addresses.end()) {
                                            nwif._addresses.emplace_back(*ia);
                                        }

                                        break;
                                    default:
                                        break;
                                    }
                                }

                                break;
                            }
                        }

                        break;
                    }
                    default:
                        break;
                    }
                }
            }
        }

        return res;
    }();

    // And a similarly immutable set of shared_ptr to network_interface_impl per shard, ready
    // to be handed out to callers with minimal overhead
    static const thread_local std::vector<shared_ptr<posix_network_interface_impl>> thread_local_interfaces = [] {
        std::vector<shared_ptr<posix_network_interface_impl>> res;
        res.reserve(global_interfaces.size());
        std::transform(global_interfaces.begin(), global_interfaces.end(), std::back_inserter(res), [](const posix_network_interface_impl& impl) {
            return make_shared<posix_network_interface_impl>(impl);
        });
        return res;
    }();

    return std::vector<network_interface>(thread_local_interfaces.begin(), thread_local_interfaces.end());
}

statistics posix_network_stack::stats(unsigned scheduling_group_id) {
    return statistics{
        bytes_sent[scheduling_group_id],
        bytes_received[scheduling_group_id],
    };
}

void posix_network_stack::clear_stats(unsigned scheduling_group_id) {
    bytes_sent[scheduling_group_id] = 0;
    bytes_received[scheduling_group_id] = 0;
}

}

}
