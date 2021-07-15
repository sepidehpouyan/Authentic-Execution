#include "uuid.h"

#include "utils.h"

typedef struct UUID_Node
{
    UUID uuid;
    struct UUID_Node* next;
} UUID_Node;

static UUID_Node* uuid_head = NULL;

int uuid_add(UUID* uuid)
{
    UUID_Node* uuid_node = malloc_aligned(sizeof(UUID_Node));

    if (uuid_node == NULL)
        return 0;

    uuid_node->uuid = *uuid;
    uuid_node->next = uuid_head;
    uuid_head = uuid_node;
    return 1;
}

UUID* uuid_get(uint16_t module_id)
{
    UUID_Node* current = uuid_head;

    while (current != NULL) {
        UUID* uuid = &current->uuid;

        if (uuid->module_id == module_id) {
            return uuid;
        }

        current = current->next;
    }

    return NULL;
}
