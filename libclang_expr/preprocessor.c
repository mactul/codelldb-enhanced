#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define SENTINEL "\n__GH567B4QFHJD__5678DGZBTDHEJF__\n"


static void write_string(int fd, const char* str, size_t len)
{
    ssize_t n;

    while((n = write(fd, str, len)) > 0)
    {
        str += n;
        len -= n;
    }
}



static int _buffer_index = 0;

static void reset_stream(void)
{
    _buffer_index = 0;
}

static bool search_occurrence_in_bytes_stream(char stream_single_byte, const char* occurrence)
{
    if(stream_single_byte == occurrence[_buffer_index])
    {
        _buffer_index++;
    }
    else
    {
        _buffer_index = stream_single_byte == occurrence[0];
    }
    if(occurrence[_buffer_index] == '\0')
    {
        return true;
    }
    return false;
}

static ssize_t read_until_sentinel(char* buffer, size_t buffer_size, ssize_t* n, int fd)
{
    reset_stream();
    while ((*n = read(fd, buffer, buffer_size)) > 0)
    {
        for(size_t i = 0; i < (size_t)*n; i++)
        {
            if(search_occurrence_in_bytes_stream(buffer[i], SENTINEL))
            {
                return (ssize_t)(i + 1);
            }
        }
    }
    return -1;
}

char* preprocess_expression(const char* file_content_before, size_t file_content_size, const char* expression)
{
    int out_fds[2];
    int in_fds[2];

    if(pipe(out_fds) < 0)
    {
        return NULL;
    }

    if(pipe(in_fds) < 0)
    {
        return NULL;
    }

    switch (fork())
    {
        case -1:
            return NULL;
        case 0:
            //child
            close(in_fds[1]);
            close(out_fds[0]);
            dup2(in_fds[0], STDIN_FILENO);
            dup2(out_fds[1], STDOUT_FILENO);
            execlp("clang", "clang", "-E", "-x", "c", "-", NULL);
            return NULL;
        default:
            close(in_fds[0]);
            close(out_fds[1]);
    }
    write_string(in_fds[1], file_content_before, file_content_size);
    write_string(in_fds[1], SENTINEL, sizeof(SENTINEL)-1);
    write_string(in_fds[1], expression, strlen(expression));
    close(in_fds[1]);

    ssize_t n;
    char buffer[512];
    ssize_t expr_offset = read_until_sentinel(buffer, 512, &n, out_fds[0]);
    if(expr_offset < 0)
    {
        return NULL;
    }

    char* preprocessed = (char*)malloc(1024);
    memcpy(preprocessed, buffer + expr_offset, n - expr_offset);
    size_t allocated = 1024;
    size_t used = n - expr_offset;

    while ((n = read(out_fds[0], preprocessed + used, allocated - used)) > 0) {
        used += n;
        if(used >= allocated)
        {
            allocated *= 2;
            void* temp = realloc(preprocessed, allocated);
            if(temp == NULL)
            {
                free(preprocessed);
                return NULL;
            }
            preprocessed = (char*)temp;
        }
    }
    close(out_fds[0]);

    preprocessed[used] = '\0';
    ssize_t end = (ssize_t)used-1;
    while(end >= 0 && (preprocessed[end] == '\n' || preprocessed[end] == '\r' || preprocessed[end] == ' ' || preprocessed[used] == '\t'))
    {
        preprocessed[end] = '\0';
        end--;
    }

    return preprocessed;
}