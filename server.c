#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/select.h>
#include <errno.h>

#define PORT 9877
#define ARRAY_SIZE 26
#define MAX_CLIENTS FD_SETSIZE

typedef enum {
    ERR_OK = 0,
    ERR_ALREADY_WRITTEN,
    ERR_UNKNOWN_COMMAND
} ErrType;

typedef struct {
    char cmd;      // Тип команды ('c' – запрос данных, 'w' – запись)
    int index;     // Используется для CMD_WRITE
} Request;

typedef struct {
    int error;                 // 0 – успех, иначе код ошибки
    char data[ARRAY_SIZE];     // Для ответа на CMD_GET_DATA
    char ch;                   // Для ответа на CMD_GET_CHAR (не используется в данном примере)
} Response;

static char data[ARRAY_SIZE];
static int listen_fd = -1;

const char reader_type = 'c';
const char writer_type = 'w';

static void cleanup(void) {
    if (listen_fd != -1)
        close(listen_fd);
}

/* Обработчик сигналов для корректного завершения */
static void handle_sigint(int signo) {
    (void)signo;
    cleanup();
    printf("Server shutdown...\n");
    exit(EXIT_SUCCESS);
}

/* Устанавливаем неблокирующий режим для сокета */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Функция обработки запроса */
static void process_request(const Request *req, Response *resp) {
    switch (req->cmd) {
        case 'c':
            memcpy(resp->data, data, ARRAY_SIZE);
            resp->error = ERR_OK;
            break;
        case 'w':
            if (!data[req->index])
                resp->error = ERR_ALREADY_WRITTEN;
            else {
                data[req->index] = 0;
                resp->error = ERR_OK;
            }
            break;
        default:
            resp->error = ERR_UNKNOWN_COMMAND;
            break;
    }
}

int main(void) {
    signal(SIGTERM, handle_sigint);
    signal(SIGINT, handle_sigint);

    for (size_t i = 0; i < ARRAY_SIZE; i++)
        data[i] = 'A' + i;

    /* Создаём серверный сокет (TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(PORT);

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        cleanup();
        exit(EXIT_FAILURE);
    }

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        cleanup();
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, 5) == -1) {
        perror("listen");
        cleanup();
        exit(EXIT_FAILURE);
    }

    /* Переводим серверный сокет в неблокирующий режим */
    if (set_nonblocking(listen_fd) == -1) {
        perror("fcntl O_NONBLOCK");
        cleanup();
        exit(EXIT_FAILURE);
    }

    /* Массив для хранения дескрипторов клиентских соединений и времени начала соединения */
    int client_fds[MAX_CLIENTS];
    clock_t client_start_times[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_fds[i] = -1;
        client_start_times[i] = 0;
    }

    printf("Server started, listening on %d\n", PORT);

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        int max_fd = listen_fd;

        /* Добавляем клиентские сокеты в набор */
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (client_fds[i] != -1) {
                FD_SET(client_fds[i], &readfds);
                if (client_fds[i] > max_fd)
                    max_fd = client_fds[i];
            }
        }

        /* Подготавливаем пустую маску сигналов */
        sigset_t sigmask;
        sigemptyset(&sigmask);

        /* Фиксируем время до обработки событий */
        clock_t start_time = clock();

        /* Ожидаем событий на сокетах с помощью pselect */
        if (pselect(max_fd + 1, &readfds, NULL, NULL, NULL, &sigmask) < 0) {
            perror("pselect");
            cleanup();
            exit(EXIT_FAILURE);
        }

        /* Принимаем новое соединение, если серверный сокет готов */
        if (FD_ISSET(listen_fd, &readfds)) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd < 0) {
                perror("accept");
            } else {
                if (set_nonblocking(client_fd) == -1) {
                    perror("fcntl client");
                    close(client_fd);
                } else {
                    /* Ищем свободное место в массиве для нового клиента */
                    int added = 0;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (client_fds[i] == -1) {
                            client_fds[i] = client_fd;
                            client_start_times[i] = start_time;
                            added = 1;
                            break;
                        }
                    }
                    if (!added) {
                        fprintf(stderr, "Too many clients. Closing new connection.\n");
                        close(client_fd);
                    }
                }
            }
        }

        /* Обработка событий на клиентских сокетах */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_fds[i] != -1 && FD_ISSET(client_fds[i], &readfds)) {
                Request req;
                ssize_t recvd = recv(client_fds[i], &req, sizeof(req), 0);
                if (recvd != sizeof(req)) {
                    fprintf(stderr, "Failed to read full request from fd %d\n", client_fds[i]);
                    close(client_fds[i]);
                    client_fds[i] = -1;
                } else {
                    Response resp;
                    process_request(&req, &resp);
                    if (send(client_fds[i], &resp, sizeof(resp), 0) != sizeof(resp))
                        perror("send to client");

                    clock_t end = clock();
                    clock_t delta = end - client_start_times[i];
                    printf("Closed connection on descriptor %d, duration: %ld ticks\n", client_fds[i], (long)delta);
                    close(client_fds[i]);
                    client_fds[i] = -1;
                }
            }
        }
    }

    cleanup();
    return 0;
}
