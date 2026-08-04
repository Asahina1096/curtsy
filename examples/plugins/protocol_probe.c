#include "curtsy_plugin.h"

#include <stdlib.h>
#include <string.h>

struct probe_context {
    const struct curtsy_host_api *host;
};

static int32_t probe_init(const struct curtsy_host_api *host, void **context) {
    struct probe_context *probe = calloc(1, sizeof(*probe));
    if (probe == NULL) return -1;
    probe->host = host;
    *context = probe;
    return 0;
}

static void probe_deinit(void *context) {
    free(context);
}

static int32_t listener_create(
    void *plugin_context,
    const struct curtsy_protocol_configuration *configuration,
    void **listener_context
) {
    struct curtsy_socket_address selected;
    if (plugin_context == NULL || configuration == NULL ||
        configuration->protocol_name_len != sizeof("probe_udp") - 1 ||
        memcmp(configuration->protocol_name, "probe_udp", sizeof("probe_udp") - 1) != 0 ||
        configuration->listen_address_count == 0) return -1;
    if (configuration->upstream_selector.is_multi == NULL ||
        configuration->upstream_selector.pick == NULL ||
        configuration->upstream_selector.report_success == NULL ||
        configuration->upstream_selector.report_failure == NULL ||
        !configuration->upstream_selector.is_multi(configuration->upstream_selector.context) ||
        !configuration->upstream_selector.pick(
            configuration->upstream_selector.context,
            NULL,
            1,
            &selected
        ) || selected.port != 9001) return -1;
    configuration->upstream_selector.report_success(
        configuration->upstream_selector.context,
        &selected
    );
    configuration->upstream_selector.report_failure(
        configuration->upstream_selector.context,
        &selected,
        2
    );
    *listener_context = plugin_context;
    return 0;
}

static void listener_noop(void *context) { (void)context; }
static void listener_update(
    void *context,
    const struct curtsy_protocol_configuration *configuration,
    uint8_t reset_sessions
) {
    (void)context;
    (void)configuration;
    (void)reset_sessions;
}
static void listener_destroy(void *context) { (void)context; }
static void listener_force_close(void *context) { (void)context; }
static size_t listener_active_count(void *context) { (void)context; return 0; }
static int64_t listener_buffered_bytes(void *context) { (void)context; return 0; }
static uint64_t listener_association_count(void *context) { (void)context; return 0; }
static void listener_metrics(void *context, struct curtsy_protocol_metrics *metrics) {
    (void)context;
    metrics->received_messages = 3;
    metrics->sent_messages = 2;
    metrics->received_bytes = 300;
    metrics->sent_bytes = 200;
    metrics->errors = 1;
}

static const struct curtsy_protocol_api protocol_api = {
    .struct_size = sizeof(struct curtsy_protocol_api),
    .name = "probe_udp",
    .drains_connections = 1,
    .create = listener_create,
    .activate = listener_noop,
    .stop_accepting = listener_noop,
    .destroy = listener_destroy,
    .update_configuration = listener_update,
    .update_backlog = NULL,
    .force_close = listener_force_close,
    .active_count = listener_active_count,
    .buffered_bytes = listener_buffered_bytes,
    .association_count = listener_association_count,
    .metrics = listener_metrics,
};

static const struct curtsy_plugin_descriptor descriptor = {
    .abi_version = CURTSY_PLUGIN_ABI_VERSION,
    .struct_size = sizeof(struct curtsy_plugin_descriptor),
    .name = "protocol_probe",
    .version = "1.0.0",
    .init = probe_init,
    .deinit = probe_deinit,
    .balancer = NULL,
    .configuration = NULL,
    .protocol = &protocol_api,
};

const struct curtsy_plugin_descriptor *curtsy_plugin_entry(void) {
    return &descriptor;
}
