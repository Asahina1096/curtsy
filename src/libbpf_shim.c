#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static int pointer_error(const void *pointer) {
    long error = libbpf_get_error(pointer);
    if (error != 0)
        return (int)error;
    if (pointer == NULL)
        return errno == 0 ? -EINVAL : -errno;
    return 0;
}

struct bpf_object *curtsy_libbpf_open(
    const void *data,
    size_t size,
    char *kernel_log,
    size_t kernel_log_size,
    int *error_out
) {
    libbpf_set_print(NULL);

    struct bpf_object_open_opts options = {0};
    options.sz = sizeof(options);
    if (kernel_log != NULL && kernel_log_size > 0) {
        kernel_log[0] = '\0';
        options.kernel_log_buf = kernel_log;
        options.kernel_log_size = kernel_log_size;
        options.kernel_log_level = 1;
    }

    struct bpf_object *object = bpf_object__open_mem(data, size, &options);
    int error = pointer_error(object);
    if (error_out != NULL)
        *error_out = error;
    return error == 0 ? object : NULL;
}

void curtsy_libbpf_close(struct bpf_object *object) {
    bpf_object__close(object);
}

int curtsy_libbpf_set_map_max_entries(
    struct bpf_object *object,
    const char *map_name,
    uint32_t max_entries
) {
    struct bpf_map *map = bpf_object__find_map_by_name(object, map_name);
    if (map == NULL)
        return -ENOENT;
    return bpf_map__set_max_entries(map, max_entries);
}

int curtsy_libbpf_set_rodata(
    struct bpf_object *object,
    const void *data,
    size_t size
) {
    struct bpf_map *map;
    bpf_object__for_each_map(map, object) {
        const char *name = bpf_map__name(map);
        if (bpf_map__is_internal(map) && name != NULL && strstr(name, ".rodata") != NULL)
            return bpf_map__set_initial_value(map, data, size);
    }
    return -ENOENT;
}

int curtsy_libbpf_set_expected_attach_type(
    struct bpf_object *object,
    const char *program_name,
    uint32_t attach_type
) {
    struct bpf_program *program = bpf_object__find_program_by_name(object, program_name);
    if (program == NULL)
        return -ENOENT;
    return bpf_program__set_expected_attach_type(program, attach_type);
}

int curtsy_libbpf_load(struct bpf_object *object) {
    return bpf_object__load(object);
}

int curtsy_libbpf_map_fd(struct bpf_object *object, const char *map_name) {
    struct bpf_map *map = bpf_object__find_map_by_name(object, map_name);
    if (map == NULL)
        return -ENOENT;
    return bpf_map__fd(map);
}

int curtsy_libbpf_program_fd(struct bpf_object *object, const char *program_name) {
    struct bpf_program *program = bpf_object__find_program_by_name(object, program_name);
    if (program == NULL)
        return -ENOENT;
    return bpf_program__fd(program);
}

int curtsy_libbpf_has_program(struct bpf_object *object, const char *program_name) {
    return bpf_object__find_program_by_name(object, program_name) == NULL ? -ENOENT : 0;
}

int curtsy_libbpf_program_type(struct bpf_object *object, const char *program_name) {
    struct bpf_program *program = bpf_object__find_program_by_name(object, program_name);
    if (program == NULL)
        return -ENOENT;
    return bpf_program__type(program);
}

int curtsy_libbpf_dup_program_fd(struct bpf_object *object, const char *program_name) {
    int program_fd = curtsy_libbpf_program_fd(object, program_name);
    if (program_fd < 0)
        return program_fd;
    int duplicate = fcntl(program_fd, F_DUPFD_CLOEXEC, 0);
    return duplicate < 0 ? -errno : duplicate;
}

struct bpf_link *curtsy_libbpf_attach_kprobe(
    struct bpf_object *object,
    const char *program_name,
    const char *function_name,
    int *error_out
) {
    struct bpf_program *program = bpf_object__find_program_by_name(object, program_name);
    if (program == NULL) {
        if (error_out != NULL)
            *error_out = -ENOENT;
        return NULL;
    }

    struct bpf_link *link = bpf_program__attach_kprobe(program, false, function_name);
    int error = pointer_error(link);
    if (error_out != NULL)
        *error_out = error;
    return error == 0 ? link : NULL;
}

void curtsy_libbpf_destroy_link(struct bpf_link *link) {
    bpf_link__destroy(link);
}
