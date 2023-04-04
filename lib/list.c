
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "lib.h"

doubly_linked_list_t* dll_create(unsigned int data_size)
{
    doubly_linked_list_t *list = (doubly_linked_list_t *)malloc(sizeof(*list));
    DIE(!list, "malloc() failed\n");

    list->head = NULL;
    list->data_size = data_size;
    list->size = 0;

    return list;
}

dll_node_t *new_node(const void *new_data, int data_size)
{
    dll_node_t *new_node = (dll_node_t *)malloc(sizeof(*new_node));
    DIE(!new_node, "malloc() failed\n");

    new_node->next = new_node->prev = NULL;
    new_node->data = malloc(data_size);
    DIE(!new_node->data, "malloc failed\n");

    memcpy(new_node->data, new_data, data_size);
    return new_node;
}

dll_node_t* dll_get_nth_node(doubly_linked_list_t* list, int n)
{
    if (n >= list->size)
        n %= list->size;

    dll_node_t *aux = list->head;
    for (int i = 0; i < n; ++i)
        aux = aux->next;

    return aux;
}

void dll_add_nth_node(doubly_linked_list_t* list, int n, const void* data,
                     unsigned int data_size)
{
    if (!list)
        return;

    if (n > list->size)
        n = list->size;

    dll_node_t *node = new_node(data, data_size);

    if (!list->size) {
        node->next = node->prev = NULL;
        list->head = node;
    } else if (!n) {
        node->next = list->head;
        node->prev = NULL;
        list->head->prev = node;
        list->head = node;
    } else {
        dll_node_t *prev_node = dll_get_nth_node(list, n - 1);
        node->next = prev_node->next;
        node->prev = prev_node;
        if (prev_node->next)
            prev_node->next->prev = node;
        prev_node->next = node;
    }

    ++list->size;
}

dll_node_t* dll_remove_nth_node(doubly_linked_list_t* list, int n)
{
    if (!list || !list->size)
        return NULL;

    dll_node_t *node;

    if (n >= list->size - 1)
        n = list->size - 1;

    if (!n) {
        node = list->head;
        list->head = list->head->next;
        if (list->size != 1)
            list->head->prev = NULL;
    } else {
        dll_node_t *prev_node = dll_get_nth_node(list, n - 1);
        node = prev_node->next;
        if (node->next)
            node->next->prev = node->prev;
        prev_node->next = node->next;
    }
    --list->size;
    return node;
}

void dll_free(doubly_linked_list_t** pp_list)
{
    dll_node_t *tmp, *node;
    int size = 0;
    if (!pp_list || !*pp_list)
        return;

    node = (*pp_list)->head;
    while (size < (*pp_list)->size) {
        ++size;
        tmp = node;
        node = node->next;
        free(tmp->data);
        free(tmp);
    }

    free(*pp_list);
    pp_list = NULL;
}
