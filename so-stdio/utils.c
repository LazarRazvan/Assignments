/*
 * Operating System Executable Loader header
 *
 * 2019, Operating Systems
 */

#include "utils.h"

/**
 * Opeartion field.
 */

/* Detect if operation is unset */
bool so_buf_op_is_unset(SO_FILE *s)
{
	return (int)s->_op == OP_UNSET ? true : false;
}

/* Detect if operation is read */
bool so_buf_op_is_read(SO_FILE *s)
{
	return (int)s->_op == OP_READ ? true : false;
}

/* Detect if operation is write */
bool so_buf_op_is_write(SO_FILE *s)
{
	return (int)s->_op == OP_WRITE ? true : false;
}

/* Set operation to unset */
void so_buf_op_set_unset(SO_FILE *s)
{
	s->_op = OP_UNSET;
}

/* Set operation to read */
void so_buf_op_set_read(SO_FILE *s)
{
	s->_op = OP_READ;
}

/* Set operation to write */
void so_buf_op_set_write(SO_FILE *s)
{
	s->_op = OP_WRITE;
}

/**
 * Buffer.
 */

/* Get buffering memory area position */
char *so_buf_get_pos(SO_FILE *s)
{
	return s->_bpos;
}

/* Get buffering memory area size (actual data) */
size_t so_buf_get_length(SO_FILE *s)
{
	return s->_blen;
}

/* Set buffering memory area size (actual data) */
void so_buf_set_length(size_t len, SO_FILE *s)
{
	s->_blen = len;
}

/* Reset buffering memory area pointer and length */
void so_buf_reset(SO_FILE *s)
{
	s->_bpos = s->_buf;
	s->_blen = 0;
}

/* Check if buffer nbytes read is available */
bool so_buf_nread_available(size_t nbytes, SO_FILE *s)
{
	return nbytes <= (s->_buf + s->_blen) - s->_bpos ? true : false;
}

/* Get number of bytes avilable for read */
size_t so_buf_get_nread_available(SO_FILE *s)
{
	return (size_t)(s->_blen - (s->_bpos - s->_buf));
}

/* Update buffer and file position for nbytes read */
void so_buf_nread_update(size_t nbytes, SO_FILE *s)
{
	s->_fpos += nbytes;
	s->_bpos += nbytes;
}

/* Check if buffer nbytes write is available */
bool so_buf_nwrite_available(size_t nbytes, SO_FILE *s)
{
	return nbytes < BUF_SIZE - s->_blen ? true : false;
}

/* Get number of bytes avilable for write */
size_t so_buf_get_nwrite_available(SO_FILE *s)
{
	return (size_t)(BUF_SIZE - s->_blen);
}

/* Update buffer and file position for nbytes read */
void so_buf_nwrite_update(size_t nbytes, SO_FILE *s)
{
	s->_fpos += nbytes;
	s->_bpos += nbytes;
	s->_blen += nbytes;
}
