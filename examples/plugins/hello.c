#include "curtsy_plugin.h"

#include <stdlib.h>
#include <string.h>

static struct curtsy_host_api host_api;
static int has_host_api;

struct hello_context {
    char *message;
};

static int32_t hello_init(const struct curtsy_host_api *host, void **plugin_context) {
    static const char message[] = "hello plugin initialized";
    struct hello_context *context = calloc(1, sizeof(*context));
    if (context == 0) return 1;
    host_api = *host;
    has_host_api = 1;
    *plugin_context = context;
    host_api.log(host_api.context, CURTSY_PLUGIN_LOG_INFO, message, sizeof(message) - 1);
    return 0;
}

static void hello_deinit(void *plugin_context) {
    static const char message[] = "hello plugin deinitialized";
    (void)plugin_context;
    if (has_host_api) {
        host_api.log(host_api.context, CURTSY_PLUGIN_LOG_INFO, message, sizeof(message) - 1);
    }
    if (plugin_context != 0) {
        struct hello_context *context = plugin_context;
        free(context->message);
        free(context);
    }
    has_host_api = 0;
}

static int32_t hello_config_prepare(
    void *plugin_context,
    const struct curtsy_plugin_config_entry *entries,
    size_t entry_count,
    void **candidate_context
) {
    size_t i;
    char *candidate = 0;
    (void)plugin_context;
    for (i = 0; i < entry_count; ++i) {
        const struct curtsy_plugin_config_entry *entry = &entries[i];
        if (entry->key_len != sizeof("message") - 1 ||
            memcmp(entry->key, "message", sizeof("message") - 1) != 0) {
            free(candidate);
            return 2;
        }
        free(candidate);
        candidate = 0;
        candidate = malloc(entry->value_len + 1);
        if (candidate == 0) return 1;
        memcpy(candidate, entry->value, entry->value_len);
        candidate[entry->value_len] = '\0';
    }
    *candidate_context = candidate;
    return 0;
}

static void hello_config_commit(void *plugin_context, void *candidate_context) {
    struct hello_context *context = plugin_context;
    static const char prefix[] = "hello plugin configured";
    free(context->message);
    context->message = candidate_context;
    host_api.log(host_api.context, CURTSY_PLUGIN_LOG_INFO, prefix, sizeof(prefix) - 1);
}

static void hello_config_discard(void *plugin_context, void *candidate_context) {
    (void)plugin_context;
    free(candidate_context);
}

static const struct curtsy_plugin_config_api hello_configuration = {
    .struct_size = sizeof(struct curtsy_plugin_config_api),
    .prepare = hello_config_prepare,
    .commit = hello_config_commit,
    .discard = hello_config_discard,
};

static int32_t first_available_build(const uint32_t *weights, size_t count, void **state) {
    (void)weights;
    (void)count;
    *state = 0;
    return 0;
}

static void first_available_destroy(void *state) {
    (void)state;
}

static size_t first_available_pick(
    void *state,
    size_t count,
    uint32_t cursor,
    uint64_t client_hash,
    uint64_t now_ns,
    void *eligibility_context,
    curtsy_upstream_eligible_fn eligible
) {
    size_t i;
    (void)state;
    (void)cursor;
    (void)client_hash;
    (void)now_ns;
    for (i = 0; i < count; ++i) {
        if (eligible(eligibility_context, i)) return i;
    }
    return 0;
}

static const struct curtsy_balancer_api first_available = {
    .struct_size = sizeof(struct curtsy_balancer_api),
    .name = "first_available",
    .build = first_available_build,
    .destroy = first_available_destroy,
    .pick = first_available_pick,
};

static const struct curtsy_plugin_descriptor descriptor = {
    .abi_version = CURTSY_PLUGIN_ABI_VERSION,
    .struct_size = sizeof(struct curtsy_plugin_descriptor),
    .name = "hello",
    .version = "1.0.0",
    .init = hello_init,
    .deinit = hello_deinit,
    .balancer = &first_available,
    .configuration = &hello_configuration,
};

const struct curtsy_plugin_descriptor *curtsy_plugin_entry(void) {
    return &descriptor;
}
