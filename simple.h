
typedef struct process_info {
    int pid;
    int uid;
    char comm[100];
    char msg[100] ;
} proc_info;

typedef struct process_file_info {
    int pid;
    int uid;
    char comm[100];
    char msg[100] ;
} proc_file_info;
