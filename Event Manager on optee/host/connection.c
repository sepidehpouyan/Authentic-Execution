#include "connection.h"

#include "utils.h"

typedef struct Node
{
    Connection connection;
    struct Node* next;
} Node;

static Node* connections_head = NULL;

int connections_add(Connection* connection)
{
    Node* node = malloc_aligned(sizeof(Node));

    if (node == NULL)
        return 0;

    node->connection = *connection;
    node->next = connections_head;
    connections_head = node;
    return 1;
}

Connection* connections_get(uint16_t conn_id)
{
    Node* current = connections_head;

    while (current != NULL) {
        Connection* connection = &current->connection;

        if (connection->conn_id == conn_id) {
            return connection;
        }

        current = current->next;
    }

    return NULL;
}
