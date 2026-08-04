#ifndef CURTSY_PLUGIN_H
#define CURTSY_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CURTSY_PLUGIN_ABI_VERSION 1u
#define CURTSY_PLUGIN_ENTRY_SYMBOL "curtsy_plugin_entry"

enum curtsy_plugin_log_level {
    CURTSY_PLUGIN_LOG_DEBUG = 0,
    CURTSY_PLUGIN_LOG_INFO = 1,
    CURTSY_PLUGIN_LOG_WARNING = 2,
    CURTSY_PLUGIN_LOG_ERROR = 3,
};

struct curtsy_plugin_config_entry {
    const char *key;
    size_t key_len;
    const char *value;
    size_t value_len;
};

struct curtsy_plugin_config_api {
    uint32_t struct_size;
    int32_t (*prepare)(
        void *plugin_context,
        const struct curtsy_plugin_config_entry *entries,
        size_t entry_count,
        void **candidate_context
    );
    void (*commit)(void *plugin_context, void *candidate_context);
    void (*discard)(void *plugin_context, void *candidate_context);
};

#define CURTSY_PROTOCOL_TCP "tcp"
#define CURTSY_PROTOCOL_UDP "udp"

enum curtsy_address_family {
    CURTSY_ADDRESS_IPV4 = 4,
    CURTSY_ADDRESS_IPV6 = 6,
};

struct curtsy_socket_address {
    uint32_t family;
    uint8_t address[16];
    uint16_t port;
    uint16_t reserved;
    uint32_t scope_id;
};

struct curtsy_upstream_selector {
    void *context;
    uint8_t (*is_multi)(void *context);
    uint8_t (*pick)(
        void *context,
        const struct curtsy_socket_address *client,
        uint64_t now_ns,
        struct curtsy_socket_address *selected
    );
    void (*report_success)(void *context, const struct curtsy_socket_address *address);
    void (*report_failure)(
        void *context,
        const struct curtsy_socket_address *address,
        uint64_t now_ns
    );
};

struct curtsy_protocol_metrics {
    uint64_t received_messages;
    uint64_t sent_messages;
    uint64_t received_bytes;
    uint64_t sent_bytes;
    uint64_t errors;
};

/* ABI v1 protocol modules may replace the existing TCP/UDP implementation or
 * register a new protocol name. Address, configuration and protocol-name
 * pointers are valid only for the duration of the callback. upstream_address
 * is the primary member; upstream_selector provides generation-stable
 * multi-upstream selection and health reporting. */
struct curtsy_protocol_configuration {
    uint32_t struct_size;
    const char *protocol_name;
    size_t protocol_name_len;
    const struct curtsy_socket_address *listen_addresses;
    size_t listen_address_count;
    struct curtsy_socket_address upstream_address;
    /* Callbacks and context remain valid until the listener is destroyed.
     * A plugin should copy this small table if it needs it after create. */
    struct curtsy_upstream_selector upstream_selector;
    int64_t connect_seconds;
    int64_t tcp_idle_seconds;
    int64_t udp_session_seconds;
    int64_t tcp_listen_backlog;
    int64_t max_tcp_buffered_bytes;
    int64_t max_udp_associations;
    int64_t worker_threads;
    int64_t udp_io_threads;
    uint8_t start_paused;
    uint8_t reserved[7];
};

struct curtsy_protocol_api {
    uint32_t struct_size;
    const char *name;
    uint8_t drains_connections;
    uint8_t reserved[7];
    int32_t (*create)(
        void *plugin_context,
        const struct curtsy_protocol_configuration *configuration,
        void **listener_context
    );
    void (*activate)(void *listener_context);
    void (*stop_accepting)(void *listener_context);
    void (*destroy)(void *listener_context);
    void (*update_configuration)(
        void *listener_context,
        const struct curtsy_protocol_configuration *configuration,
        uint8_t reset_sessions
    );
    int32_t (*update_backlog)(void *listener_context, int32_t backlog);
    void (*force_close)(void *listener_context);
    size_t (*active_count)(void *listener_context);
    int64_t (*buffered_bytes)(void *listener_context);
    uint64_t (*association_count)(void *listener_context);
    /* Optional cumulative counters. Hosts that predate this trailing field
     * accept a shorter struct_size and report zero plugin metrics. */
    void (*metrics)(
        void *listener_context,
        struct curtsy_protocol_metrics *metrics
    );
};

struct curtsy_host_api {
    uint32_t abi_version;
    uint32_t struct_size;
    void *context;
    void (*log)(void *context, uint32_t level, const char *message, size_t message_len);
};

/* The host API pointer remains valid until the plugin's deinit callback
 * returns. A plugin may retain the pointer for that lifetime only. */

struct curtsy_plugin_descriptor {
    uint32_t abi_version;
    uint32_t struct_size;
    const char *name;
    const char *version;
    int32_t (*init)(const struct curtsy_host_api *host, void **plugin_context);
    void (*deinit)(void *plugin_context);
    /* Optional ABI-v1 extension. Older lifecycle-only descriptors end before
     * this field and advertise the smaller struct_size. */
    const struct curtsy_balancer_api *balancer;
    /* Optional namespaced configuration extension. */
    const struct curtsy_plugin_config_api *configuration;
    /* Optional runtime replacement for the built-in TCP or UDP data plane. */
    const struct curtsy_protocol_api *protocol;
};

typedef uint8_t (*curtsy_upstream_eligible_fn)(void *context, size_t index);

struct curtsy_balancer_api {
    uint32_t struct_size;
    const char *name;
    int32_t (*build)(const uint32_t *weights, size_t count, void **state);
    void (*destroy)(void *state);
    size_t (*pick)(
        void *state,
        size_t count,
        uint32_t cursor,
        uint64_t client_hash,
        uint64_t now_ns,
        void *eligibility_context,
        curtsy_upstream_eligible_fn eligible
    );
};

typedef const struct curtsy_plugin_descriptor *(*curtsy_plugin_entry_fn)(void);

#ifdef __cplusplus
}
#endif

#endif
