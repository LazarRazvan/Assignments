/*
 * Operating System Executable Loader header
 *
 * 2019, Operating Systems
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* SO FILE error flag values */
#define SO_FFLUSH					1
#define SO_FSEEK					2
#define SO_FGETC					3
#define SO_FREAD					4

/* Buffering memory area size */
#define BUF_SIZE					4096

/* SO FILE last opeartion enum */
typedef enum _last_op {
	OP_UNSET = 0,
	OP_READ,
	OP_WRITE
} last_op;

/* SO_FILE data structure */
typedef struct _so_file {
	char		*_bpos;				/* Buffering memory area position pointer */
	off_t		_fpos;				/* File read/write position */
	int			_fd;				/* File descriptor */
	int			_pid;				/* Child process pid */
	short		_blen;				/* Buffering memory area length */
	char		_feof;				/* Signal if end of file reached or not */
	char		_ferr;				/* Signal if an error occured on file ops */
	last_op		_op;				/* Last buffer operation (read/write) */
	char		_buf[BUF_SIZE];		/* Buffering memory area */
} SO_FILE;


/* SO_FILE helper functions */

bool so_buf_op_is_unset(SO_FILE *s);
bool so_buf_op_is_read(SO_FILE *s);
bool so_buf_op_is_write(SO_FILE *s);
void so_buf_op_set_unset(SO_FILE *s);
void so_buf_op_set_read(SO_FILE *s);
void so_buf_op_set_write(SO_FILE *s);

char *so_buf_get_pos(SO_FILE *s);
size_t so_buf_get_length(SO_FILE *s);
void so_buf_set_length(size_t len, SO_FILE *s);
void so_buf_reset(SO_FILE *s);
bool so_buf_nread_available(size_t nbytes, SO_FILE *s);
size_t so_buf_get_nread_available(SO_FILE *s);
void so_buf_nread_update(size_t nbytes, SO_FILE *s);
bool so_buf_nwrite_available(size_t nbytes, SO_FILE *s);
size_t so_buf_get_nwrite_available(SO_FILE *s);
void so_buf_nwrite_update(size_t nbytes, SO_FILE *s);

/* Get character from buffer and increment positions */
static inline char _buf_fgetc(SO_FILE *s)
{
	s->_fpos++;
	return *(s->_bpos++);
}

/* Check if buffer fputc is available */
static inline bool _buf_fputc_available(SO_FILE *s)
{
	return s->_bpos < s->_buf + BUF_SIZE ? true : false;
}

/* Get character from buffer and increment positions */
static inline void _buf_fputc(int c, SO_FILE *s)
{
	s->_fpos++;
	*(s->_bpos++) = c;
}

/* Get character from buffer and increment positions */
static inline void _buf_fread(size_t bytes, SO_FILE *s)
{
	s->_fpos += bytes;
	s->_bpos += bytes;
}

/* Check if buffer fread is available */
static inline bool _buf_fwrite_available(size_t bytes, SO_FILE *s)
{
	return bytes < BUF_SIZE - s->_blen ? true : false;
}

/* Get character from buffer and increment positions */
static inline void _buf_fwrite(size_t bytes, SO_FILE *s)
{
	s->_fpos += bytes;
	s->_bpos += bytes;
}
#endif	/* UTILS_H */
