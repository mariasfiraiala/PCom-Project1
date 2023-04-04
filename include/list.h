#ifndef _LIST_H_
#define _LIST_H_

typedef struct dll_node_t
{
    void *data;
    struct dll_node_t *prev, *next;
} dll_node_t;

typedef struct doubly_linked_list_t
{
    dll_node_t *head;
    unsigned int data_size;
    int size;
} doubly_linked_list_t;

/*
* @brief -> creates a doubly linked list
* @param -> data_size = the size of the values that are going to be stored
* @return -> returns the newly created list
*/
doubly_linked_list_t* dll_create(unsigned int data_size);

/*
* @brief -> creates a new node
* @param -> new_data = the info that we want to have in the said node
* @param -> data_size = the size of the data that is being inserted in the node
* @return -> the freshly created node
*/
dll_node_t *new_node(const void *new_data, int data_size);

/*
* @brief -> finds the nth node in a given list
* @param -> list = the list in which we search for values
* @param -> n = the index we are interested in
* @return -> returns the node at the given index
*/
dll_node_t* dll_get_nth_node(doubly_linked_list_t* list, int n);

/*
* @brief -> inserts a new node in a doubly linked list
* @param -> list = the list that needs to be updated
* @param -> n = the index at which the new node will be inserted
* @param -> data = the value for the entry
* @param -> data_size = the size of the data that is being inserted in the node
* @return -> none, we directly modify the list
*/
void dll_add_nth_node(doubly_linked_list_t* list, int n,
                     const void* data, unsigned int data_size);

/*
* @brief -> removes the nth node
* @param -> list = the list from which we delete nodes
* @param -> n = the index of the node that we want to be removed
* @return -> returns the now deleted node
*/
dll_node_t* dll_remove_nth_node(doubly_linked_list_t* list, int n);

/*
* @brief -> frees a whole list and its dinamically alocated values
* @param -> pp_list = the list that it's going to be freed
* @return -> none, the list is being persistently modified as it is sent as a
*            double pointer
*/
void dll_free(doubly_linked_list_t** pp_list);

#endif /* _LIST_H_ */
