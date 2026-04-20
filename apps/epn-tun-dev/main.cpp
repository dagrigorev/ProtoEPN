// epn-tun-dev: Network setup tool for transparent EPN tunneling
//
// Creates a TUN interface and sets up iptables rules so that ALL TCP traffic
// from this machine is transparently routed through the EPN tunnel — no
// per-application SOCKS5 configuration required.
//
// Flow after setup:
//   [Any app] → TCP connect anywhere
//   → iptables OUTPUT -j REDIRECT → localhost:tproxy_port
//   → epn-tun-client (transparent mode) → EPN (3-hop onion) → real server
//
// Usage (as root):
//   epn-tun-dev setup   --tproxy-port 1081 --epn-relay 127.0.0.1
//   epn-tun-dev teardown --tproxy-port 1081
//   epn-tun-dev status

#include <epn/observability/log.hpp>
#include <CLI/CLI.hpp>
#include <asio.hpp>

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <iostream>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#ifdef __linux__
#include <linux/if_tun.h>
#endif

using namespace epn;

// ─── Run a shell command, return exit code ─────────────────────────────────────
static int run(const std::string& cmd, bool quiet = false) {
    if (!quiet) LOG_DEBUG("$ {}", cmd);
    int rc = std::system(cmd.c_str());
    if (rc != 0 && !quiet) LOG_WARN("Command failed (exit {}): {}", rc, cmd);
    return rc;
}

// ─── TUN interface creation ────────────────────────────────────────────────────
#ifdef __linux__
static int create_tun(const std::string& name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        LOG_ERROR("Cannot open /dev/net/tun: {} (root required)", strerror(errno));
        return -1;
    }

    struct ifreq ifr{};
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN mode, no packet info header
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        LOG_ERROR("TUNSETIFF failed: {}", strerror(errno));
        close(fd);
        return -1;
    }

    LOG_INFO("TUN interface '{}' created (fd={})", name, fd);
    return fd;
}

static bool configure_tun(const std::string& name,
                           const std::string& local_ip,
                           const std::string& peer_ip,
                           int mtu = 1500)
{
    // Set interface UP with IP address
    if (run("ip link set " + name + " up") != 0) return false;
    if (run("ip addr add " + local_ip + "/30 peer " + peer_ip + " dev " + name) != 0) return false;
    if (run("ip link set " + name + " mtu " + std::to_string(mtu)) != 0) return false;
    LOG_INFO("TUN {}: local={} peer={} mtu={}", name, local_ip, peer_ip, mtu);
    return true;
}
#endif

// ─── iptables rule management ─────────────────────────────────────────────────
struct IptablesConfig {
    uint16_t    tproxy_port;
    std::vector<std::string> exclude_cidrs;  // Do NOT redirect these (relay IPs, etc.)
    std::string chain_name{"EPN_REDIRECT"};
};

static bool setup_iptables(const IptablesConfig& cfg) {
    LOG_INFO("Setting up iptables transparent proxy rules...");
    LOG_INFO("  Redirecting TCP → localhost:{}", cfg.tproxy_port);
    LOG_INFO("  Exclusions: {} CIDRs", cfg.exclude_cidrs.size());

    auto port = std::to_string(cfg.tproxy_port);
    auto& chain = cfg.chain_name;

    // Create EPN chain (ignore error if already exists)
    run("iptables -t nat -N " + chain, true);
    run("iptables -t nat -F " + chain, true);  // Flush if exists

    // Always skip loopback (relay connections live here in dev setups)
    run("iptables -t nat -A " + chain + " -o lo -j RETURN");

    // Skip private/link-local networks (RFC1918 + localhost ranges)
    for (auto& cidr : {"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                        "192.168.0.0/16", "169.254.0.0/16"}) {
        run("iptables -t nat -A " + chain + " -d " + cidr + " -j RETURN");
    }

    // Skip user-specified CIDRs (EPN relay/server IPs)
    for (auto& cidr : cfg.exclude_cidrs) {
        run("iptables -t nat -A " + chain + " -d " + cidr + " -j RETURN");
    }

    // Skip EPN process's own packets (marked with 0xEAB5 = 60085)
    // epn-tun-client sets SO_MARK on its outgoing EPN tunnel socket
    run("iptables -t nat -A " + chain + " -m mark --mark 0xEAB5 -j RETURN");

    // Redirect remaining TCP to transparent proxy port
    if (run("iptables -t nat -A " + chain + " -p tcp -j REDIRECT --to-ports " + port) != 0) {
        LOG_ERROR("Failed to add REDIRECT rule — is iptables available and running as root?");
        return false;
    }

    // Hook into OUTPUT chain (locally generated traffic)
    run("iptables -t nat -D OUTPUT -p tcp -j " + chain, true);  // Remove old if exists
    if (run("iptables -t nat -A OUTPUT -p tcp -j " + chain) != 0) {
        LOG_ERROR("Failed to hook EPN chain into OUTPUT");
        return false;
    }

    LOG_INFO("iptables rules installed successfully");
    return true;
}

static bool teardown_iptables(const IptablesConfig& cfg) {
    LOG_INFO("Removing iptables transparent proxy rules...");
    auto& chain = cfg.chain_name;

    run("iptables -t nat -D OUTPUT -p tcp -j " + chain, true);
    run("iptables -t nat -F " + chain, true);
    run("iptables -t nat -X " + chain, true);

    LOG_INFO("iptables rules removed");
    return true;
}

static void show_status(const IptablesConfig& cfg) {
    std::cout << "\n=== EPN Transparent Proxy Status ===\n\n";

    // Check if chain exists
    int rc = run("iptables -t nat -L " + cfg.chain_name + " -n --line-numbers", true);
    if (rc == 0) {
        std::cout << "iptables chain '" << cfg.chain_name << "': ACTIVE\n";
        run("iptables -t nat -L " + cfg.chain_name + " -n --line-numbers");
    } else {
        std::cout << "iptables chain '" << cfg.chain_name << "': NOT INSTALLED\n";
    }

    std::cout << "\nOUTPUT chain:\n";
    run("iptables -t nat -L OUTPUT -n | grep " + cfg.chain_name);

    std::cout << "\nTest with:\n";
    std::cout << "  curl --max-time 5 http://example.com   (should route via EPN)\n\n";
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    CLI::App app{"EPN Tunnel Device Setup"};
    app.require_subcommand(1);

    // Common options
    int         tproxy_port = 1081;
    std::string chain       = "EPN_REDIRECT";
    std::vector<std::string> exclude_ips;
    bool        debug       = false;

    // ── setup subcommand ──────────────────────────────────────────────────────
    auto* setup_cmd = app.add_subcommand("setup",
        "Install iptables rules for transparent TCP tunneling");
    setup_cmd->add_option("--tproxy-port", tproxy_port,
        "Port where epn-tun-client listens (transparent mode)")->default_val(1081);
    setup_cmd->add_option("--exclude", exclude_ips,
        "IP/CIDR to exclude from tunnel (relay hosts, etc.)");
    setup_cmd->add_option("--chain", chain, "iptables chain name")->default_val("EPN_REDIRECT");
    setup_cmd->add_flag("-d,--debug", debug, "Debug logging");

    // ── teardown subcommand ───────────────────────────────────────────────────
    auto* teardown_cmd = app.add_subcommand("teardown", "Remove iptables tunnel rules");
    teardown_cmd->add_option("--chain", chain, "iptables chain name")->default_val("EPN_REDIRECT");

    // ── status subcommand ─────────────────────────────────────────────────────
    auto* status_cmd  = app.add_subcommand("status",  "Show current tunnel status");
    status_cmd->add_option("--chain", chain, "iptables chain name")->default_val("EPN_REDIRECT");

    CLI11_PARSE(app, argc, argv);

    observability::init_logger("epn-tun-dev", debug);

    // Check root
    if (geteuid() != 0) {
        std::cerr << "[ERROR] epn-tun-dev requires root privileges (sudo)\n";
        return 1;
    }

    IptablesConfig cfg;
    cfg.tproxy_port   = static_cast<uint16_t>(tproxy_port);
    cfg.exclude_cidrs = exclude_ips;
    cfg.chain_name    = chain;

    if (app.got_subcommand("setup")) {
        LOG_INFO("EPN Tunnel Device Setup");
        LOG_INFO("  Transparent proxy port: {}", tproxy_port);
        LOG_INFO("  Excluded CIDRs: {}", exclude_ips.size());

        if (!setup_iptables(cfg)) {
            LOG_CRITICAL("Setup failed");
            return 1;
        }

        std::cout << "\n";
        std::cout << "┌─────────────────────────────────────────────────────┐\n";
        std::cout << "│          EPN Transparent Tunnel: ACTIVE             │\n";
        std::cout << "├─────────────────────────────────────────────────────┤\n";
        std::cout << "│ All TCP traffic → EPN tunnel (port " << tproxy_port << ")            │\n";
        std::cout << "│                                                     │\n";
        std::cout << "│ Start the tunnel client:                            │\n";
        std::cout << "│   ./epn-tun-client --disc-port 8000 \\               │\n";
        std::cout << "│     --transparent --tproxy-port " << tproxy_port << "               │\n";
        std::cout << "│                                                     │\n";
        std::cout << "│ Then any TCP request is automatically tunneled.     │\n";
        std::cout << "│ To undo: sudo epn-tun-dev teardown                 │\n";
        std::cout << "└─────────────────────────────────────────────────────┘\n\n";

    } else if (app.got_subcommand("teardown")) {
        teardown_iptables(cfg);
        std::cout << "EPN tunnel rules removed.\n";

    } else if (app.got_subcommand("status")) {
        show_status(cfg);
    }

    return 0;
}
