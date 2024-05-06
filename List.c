#include "List.h"

int list_constructor(List *l, bool exclusive) {
    if(l){
        l->length = 0;
        l->exclusive = exclusive;
    }
    return 0;
}

int list_add_element(List *l, void *e) {
    if(l == NULL)
        return 1;
    if(e == NULL)    
        return 2;

    Element *element;
    element = (Element *)malloc(sizeof(Element));
    element->item = e;
    element->index = l->length + 1;
    
    if(l->length == 0) {
        element->prev = NULL;
        element->next = NULL;
        l->first_element = element;
        l->length = 1;
    } else {
        Element *next_element = l->first_element;
        bool complete = false;
        while(complete == false) {
            if(next_element->next == NULL) {
                next_element->next = element;
                element->prev = next_element;
                l->length += 1;
                complete = true;
            } else {
                next_element = next_element->next;
            }
        }
    }
    return 0;
}

int list_del_element(List *l, size_t index) {
    if(l == NULL)
        return 1;
    if(l->length == 0)
        return 2;
    
    Element *next_element = l->first_element;
    Element *prev_element = l->first_element;
    bool complete = false;
    bool deleted  = false;

    while(complete == false) {
        if(next_element->index == index) {
            prev_element->next = next_element->next;
            next_element = next_element->next;
        }
        else if(next_element->next == NULL) {
            next_element-> index -= 1;
            l->length -= 1;
            complete = true;
        } else if (deleted == true){
            next_element-> index -= 1;
            next_element = next_element->next;
        } else {
            prev_element = next_element;
            next_element = next_element->next;
        }
    }

    return 0;
}

int list_get_element(List *l, Element *e, size_t index) {
    if(l == NULL)
        return 1;
    if(e == NULL)    
        return 2;
    
    Element *next_element = l->first_element;
    for(size_t i = 0; i <= index; i++){
        if(i == index) {
            *e = *next_element;
            return 0;
        }
        next_element = next_element->next;
    }
    return 3;
}