#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef struct {
    uint32_t id;
    uint32_t type;
    char data[24];
} EventRecord;
void process_events(uint32_t num_events, const char* event_data) {
    uint32_t total_size = num_events * sizeof(EventRecord);
    EventRecord* records = (EventRecord*)malloc(total_size);
    if (!records) {
        return;
    }
    for (uint32_t i = 0; i < num_events; i++) {
        memcpy(&records[i], event_data + (i * sizeof(EventRecord)), sizeof(EventRecord));
        printf("Processed event %u\n", records[i].id);
    }
    free(records);
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <num_events>\n", argv[0]);
        return 1;
    }
    uint32_t count = (uint32_t)strtoul(argv[1], NULL, 10);
    char* dummy_data = (char*)calloc(100, sizeof(EventRecord));
    process_events(count, dummy_data);
    free(dummy_data);
    return 0;
}
