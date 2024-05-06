#ifndef _LIST_H_
#define _LIST_H_

#include <stdbool.h>
#include <stdlib.h>

typedef struct Element {
    void *item;
    size_t index;
    void *next;
    void *prev;
} Element;

typedef struct List {
    int length;
    bool exclusive;
    Element *first_element;
} List;

extern int list_constructor(List *l, bool exclusive);
extern int list_add_element(List *l, void *element_address);
extern int list_del_element(List *l, size_t index);
extern int list_get_element(List *l, Element *e, size_t index);

#endif