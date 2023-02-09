
typedef struct process_info {
    int pid;
    int uid;
    char comm[200];
    char msg[200] ;
} proc_info;

typedef struct process_file_info {
    int pid;
    int uid;
    char comm[200];
    char msg[200] ;
} proc_file_info;
