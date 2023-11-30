/*
 * Operating System Executable Loader header
 *
 * 2019, Operating Systems
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <errno.h>

#include "utils.h"
#include "so_stdio.h"

/* min function */
int min(int num1, int num2)
{
	return (num1 > num2) ? num2 : num1;
}

/**
 * SO File Open.
 *
 * @pathname:	File path name.
 * @mode	:	File open flags.
 *
 * Parse mode to detect file open flags and alloc memory for
 * SO_FILE data structure.
 *
 * Return SO_FILE structure on success and NULL otherwise.
 */
SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	mode_t m = 0;
	SO_FILE *stream;
	int m_size, flags = 0;

	/* Validate mode size and format */
	m_size = strlen(mode);
	if (!m_size || m_size > 2 || (m_size == 2 && mode[1] != '+'))
		goto error;

	/* Flags detection */
	switch (*mode) {
	case 'r':
		if (m_size == 2)
			flags = O_RDWR;
		else
			flags = O_RDONLY;

		break;
	case 'w':
		m = 0666;
		if (m_size == 2)
			flags = O_RDWR | O_TRUNC | O_CREAT;
		else
			flags = O_WRONLY | O_TRUNC | O_CREAT;

		break;
	case 'a':
		m = 0666;
		if (m_size == 2)
			flags = O_RDWR | O_APPEND | O_CREAT;
		else
			flags = O_WRONLY | O_APPEND | O_CREAT;

		break;
	default:
		goto error;
	}

	/* Create SO_FILE space */
	stream = calloc(1, sizeof(SO_FILE));
	if (!stream)
		goto error;

	/* Open file */
	stream->_fd = open(pathname, flags, m);
	if (stream->_fd < 0)
		goto free_space;


	/* Move buffer position pointer to start of memory area */
	stream->_bpos = stream->_buf;

	/* Set file position from file descriptor */
	stream->_fpos = lseek(stream->_fd, 0, SEEK_CUR);
	if (stream->_fpos == -1)
		goto free_space;

	/* All other fields are initialized based on calloc usage */
	return stream;

free_space:
	free(stream);

error:
	return NULL;
}

/**
 * SO File Close.
 *
 * @stream:		SO_FILE structure for an open file.
 *
 * Close SO_FILE file. Flush the buffer (will only flush for write last
 * operation), try to close the file descriptor and free space.
 *
 * Return 0 on success or SO_EOF on error.
 */
int so_fclose(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	/* Buffer flush */
	if (so_fflush(stream) == SO_EOF) {
		close(stream->_fd);
		free(stream);
		return SO_EOF;
	}

	/* Close file */
	if (close(stream->_fd) == -1) {
		free(stream);
		return SO_EOF;
	}

	free(stream);

	return 0;
}

/**
 *	SO File integer descriptor.
 *
 *	@stream:	SO_FILE structure for an open file.
 *
 *	Return file descriptor on success and SO_EOF on error.
 */
int so_fileno(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	return stream->_fd;
}

/**
 * SO File flush.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Flush buffer only if last operation was a write one. Write entire buffer
 * content to file and reset it (position to start of buffer and length 0).
 *
 * Function may set stream error to SO_FFLUSH error if write call fails.
 *
 * Return 0 on success and SO_EOF otherwise.
 */
int so_fflush(SO_FILE *stream)
{
	ssize_t ret;
	size_t bytes = 0, len;

	if (!stream)
		return SO_EOF;

	/* Nothing to do for unset or read last operation */
	if (so_buf_op_is_read(stream) || so_buf_op_is_unset(stream))
		return 0;

	/* Write buffer to file, on error set flag */
	len = so_buf_get_length(stream);
	while (len) {
		ret = write(stream->_fd, stream->_buf + bytes, len);
		if (ret == -1) {
			stream->_ferr = SO_FFLUSH;
			return SO_EOF;
		}

		bytes += ret;
		len -= ret;
	}

	/* Reset buffer */
	so_buf_reset(stream);

	return 0;
}

/**
 * SO File seek.
 *
 * @stream:	SO_FILE structure for an open file.
 * @offset: SO_FILE offset relative to whence.
 * @whence:	SO_FILE whence position.
 *
 * Update SO_FILE cursor position.
 * Function invalidate buffer, for read buffer is reset and for write
 * flush is called. On success, last operation performed is reset to
 * unset.
 *
 * Function may set stream error to SO_FSEEK error if lseek call fails.
 *
 * Return 0 on success and -1 otherwise.
 */
int so_fseek(SO_FILE *stream, long offset, int whence)
{
	if (!stream)
		return -1;

	/* Invalidate buffer based on last operation */
	if (so_buf_op_is_read(stream)) {
		so_buf_reset(stream);
	} else if (so_buf_op_is_write(stream)) {
		if (so_fflush(stream) == SO_EOF)
			return -1;
	}

	/* Update file position, on error set flag */
	stream->_fpos = lseek(stream->_fd, offset, whence);
	if (stream->_fpos == -1) {
		stream->_ferr = SO_FSEEK;
		return -1;
	}

	/* Reset last operation */
	so_buf_op_set_unset(stream);

	return 0;
}

/**
 * SO File ftell.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Return file read/write cursor on success and -1 otherwise.
 */
long so_ftell(SO_FILE *stream)
{
	if (!stream)
		return -1;

	return stream->_fpos;
}

/**
 * SO File fread.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Read nbytes from buffer.
 * If previous opeartion was a write one flush and repopulate the buffer.
 * If nbytes read is available, return it and increment buffer and file
 * position. Otherwise, buffer is full so reset it and read data from file,
 * return character and increment buffer and file position and update new
 * buffer length (bytes read). Update last operation to read only on success.
 *
 * Function may set end of file flag or error flag to SO_FREAD.
 *
 * Return number of elements read from file on success or SO_EOF otherwise.
 */
size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	ssize_t ret;
	size_t b_read_available, b_read = 0, b_to_read = size * nmemb;

	if (!stream)
		return 0;

	/* Flush buffer if last operation is write */
	if (so_buf_op_is_write(stream) && (so_fflush(stream) == SO_EOF))
		return 0;

	/* Check if n bytes read available */
	if (so_buf_nread_available(b_to_read, stream)) {
		memcpy(ptr, so_buf_get_pos(stream), b_to_read);
		so_buf_nread_update(b_to_read, stream);
		so_buf_op_set_read(stream);

		return nmemb;
	}

	/* Not enough elements in buffer */
	while (b_to_read) {

		/* Get buffer available read bytes */
		b_read_available = so_buf_get_nread_available(stream);

		/* If no bytes left, repopulate buffer from file */
		if (b_read_available == 0) {
			so_buf_reset(stream);
			ret = read(stream->_fd, stream->_buf, BUF_SIZE);
			if (ret == 0) {
				stream->_feof = 1;
				goto ret;	/* end of file */
			}

			if (ret == -1) {
				stream->_ferr = SO_FREAD;
				return 0;	/* error */
			}

			/* Update buffer length and available read bytes */
			so_buf_set_length(ret, stream);
			b_read_available = ret;
		}

		/* Make sure don't read more then requested */
		b_read_available = min(b_to_read, b_read_available);
		memcpy(ptr + b_read, stream->_bpos, b_read_available);
		so_buf_nread_update(b_read_available, stream);

		/* Update bytes read and bytes left to read */
		b_read += b_read_available;
		b_to_read -= b_read_available;
	}


ret:
	so_buf_op_set_read(stream);
	return b_read/size;
}


/**
 * SO File fwrite.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Write nbytes to buffer.
 * If previous operation was a read one reset the buffer. If nbytes write
 * is available, write it and upd buffer/file positions and buffer length.
 * Otherwise, buffer is full so flush it and write byte and update buffer/file
 * position and increment buffer length. Update last operation flag at the
 * beginning to make sure flush is not affected.
 *
 * Return number of elements written to file on success or SO_EOF otherwise.
 */
size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	size_t b_write_available, b_written = 0, b_to_write = size * nmemb;

	if (!stream)
		return SO_EOF;

	/* Reset buffer if last operations is read or unset */
	if (so_buf_op_is_read(stream) || so_buf_op_is_unset(stream))
		so_buf_reset(stream);

	/* Set write operation */
	so_buf_op_set_write(stream);

	/* Check if can write character from buffer */
	if (_buf_fwrite_available(b_to_write, stream)) {
		memcpy(so_buf_get_pos(stream), ptr, b_to_write);
		so_buf_nwrite_update(b_to_write, stream);

		return nmemb;
	}

	/* Not enough space in buffer */
	while (b_to_write) {

		/* Get buffer avilable write bytes */
		b_write_available = so_buf_get_nwrite_available(stream);

		/* If not enough space, flush the buffer */
		if (!b_write_available) {
			if (so_fflush(stream) == SO_EOF)
				return 0;

			/* Update available write bytes */
			b_write_available = BUF_SIZE;
		}

		/* Make sure don't write more then requested */
		b_write_available = min(b_to_write, b_write_available);
		memcpy(stream->_bpos, ptr + b_written, b_write_available);
		so_buf_nwrite_update(b_write_available, stream);

		/* Update bytes written and bytes left to write */
		b_written += b_write_available;
		b_to_write -= b_write_available;
	}

	return b_written/size;
}


/**
 * SO File fgetc.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Read a character from buffer.
 * If previous opeartion was a write one flush and repopulate the buffer.
 * If one byte read is available, return it and increment buffer and file
 * position. Otherwise, buffer is full so reset it and read data from file,
 * return character and increment buffer and file position and update new
 * buffer length (bytes read). Update last operation to read only on success.
 *
 * Function may set end of file flag or error flag to SO_FGETC.
 *
 * Return a character from file on success or SO_EOF otherwise.
 */
int so_fgetc(SO_FILE *stream)
{
	int c;
	ssize_t ret;

	if (!stream)
		return SO_EOF;

	/* Flush buffer if last operation is write */
	if (so_buf_op_is_write(stream) && (so_fflush(stream) == SO_EOF))
		return SO_EOF;

	/* Check if buffer 1 byte read avaiable */
	if (so_buf_nread_available(1, stream)) {
		c = *(char *)so_buf_get_pos(stream);
		so_buf_nread_update(1, stream);
		so_buf_op_set_read(stream);

		return c;
	}

	/* Buffer is full, read from file */
	so_buf_reset(stream);
	ret = read(stream->_fd, stream->_buf, BUF_SIZE);
	if (ret == 0) {
		stream->_feof = 1;
		return SO_EOF;
	}

	if (ret == -1) {
		stream->_ferr = SO_FGETC;
		return SO_EOF;
	}

	/* Set buffer length and update positions */
	so_buf_set_length(ret, stream);
	c = *(char *)so_buf_get_pos(stream);
	so_buf_nread_update(1, stream);
	so_buf_op_set_read(stream);

	return c;
}

/**
 * SO File fputc.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Write a character to buffer.
 * If previous operation was a read one reset the buffer. If one byte write
 * is available, write it and increment buffer/file position and increment
 * buffer length. Otherwise, buffer is full so flush it and write byte and
 * update buffer/file position and increment buffer length. Update last
 * operation at the beginning to not affect flush.
 *
 * Return a character from file on success or SO_EOF otherwise.
 */
int so_fputc(int c, SO_FILE *stream)
{

	if (!stream)
		return SO_EOF;

	/* Reset buffer if last operations is read */
	if (so_buf_op_is_read(stream))
		so_buf_reset(stream);

	/* Set operation to write */
	so_buf_op_set_write(stream);

	/* Check if can write character from buffer */
	if (so_buf_nwrite_available(1, stream)) {
		*(char *)so_buf_get_pos(stream) = c;
		so_buf_nwrite_update(1, stream);

		return c;
	}

	/* Buffer is full, flush it */
	if (so_fflush(stream) == SO_EOF)
		return SO_EOF;

	/* Write byte, update positions and increment buffer length */
	*(char *)so_buf_get_pos(stream) = c;
	so_buf_nwrite_update(1, stream);

	return c;
}

/**
 * SO File feof.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Return !0 if end of file flag is set and 0 otherwise.
 */
int so_feof(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	return stream->_feof;
}

/**
 * SO File ferror.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Return (SO_FFLUS, SO_FSEEK, SO_FGETC, SO_FREAD) on error and 0 otherwise.
 */
int so_ferror(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	return stream->_ferr;
}

/**
 * SO File popen.
 *
 * @command:	Command to be executed by child process.
 * @type:		Child process flags (r/w).
 *
 * Run a new process to execute a command.
 * Inspect type and detect pipe end for child and parent process.
 * - "r" : child pipe end STDOUT; parent pipe end STDION
 * - "w" : child pipe end STDIN; parent pipe end STDOUT
 *
 * Create pipe for communication between parent and child process. When forking
 * each parent and child close the other side of the pipe for communication.
 * If fork success asign parent pipe end to file descriptor, intialize buffer
 * position and save pid.
 *
 * Return stream memory on success and NULL otherwise.
 */
SO_FILE *so_popen(const char *command, const char *type)
{
	pid_t pid;
	SO_FILE *stream;
	int pds[2], p_parent, p_child;

	/* Check type size */
	if (strlen(type) != 1)
		goto error;

	/* Parse type and detect pipe ends for parent and child */
	switch (*type) {
	case 'r':
		p_child = STDOUT_FILENO;
		p_parent = STDIN_FILENO;
		break;
	case 'w':
		p_child = STDIN_FILENO;
		p_parent = STDOUT_FILENO;
		break;
	default:
		goto error;
	}

	/* Create pipe */
	if (pipe(pds) == -1)
		goto error;

	/* Create child process */
	pid = fork();
	switch (pid) {
	case -1:
		/* ERROR FORKING */

		close(pds[STDIN_FILENO]);
		close(pds[STDOUT_FILENO]);
		goto error;

	case 0:
		/* CHILD PROCESS */

		/* Close parent pipe end */
		close(pds[p_parent]);

		/* Redirect stdin/stdout */
		dup2(pds[p_child], p_child);

		/* Run command */
		execl("/bin/sh", "sh", "-c", command, NULL);

		/* Only if exec failed */
		close(pds[p_child]);
		exit(-1);

	default:
		/* PARENT PROCESS */

		/* close child pipe end */
		if (close(pds[p_child]) == -1)
			goto error;

		/* Create SO_FILE space */
		stream = calloc(1, sizeof(SO_FILE));
		if (!stream)
			goto error;

		/* Assign pipe end as file descriptor */
		stream->_fd = pds[p_parent];

		/* Move buffer position pointer to start of memory area */
		stream->_bpos = stream->_buf;

		/* Assing child process pid */
		stream->_pid = pid;

		/* All other fields are initialized based on calloc usage */
		return stream;
	}

error:
	return NULL;
}

/**
 * SO File pclose.
 *
 * @stream:	SO_FILE structure for an open file.
 *
 * Close a file opended with so_popen call.
 * Flush the buffer, close the associated file descriptor and wait for child
 * process.
 *
 * Return -1 on error or waitpid status on success.
 */
int so_pclose(SO_FILE *stream)
{
	int status = 0;

	if (!stream)
		return -1;

	/* Buffer flush */
	if (so_fflush(stream) == SO_EOF) {
		close(stream->_fd);
		waitpid(stream->_pid, &status, 0);
		free(stream);
		return -1;
	}

	/* Close file */
	if (close(stream->_fd) == -1) {
		waitpid(stream->_pid, &status, 0);
		free(stream);
		return -1;
	}

	/* Wait for child process */
	if (waitpid(stream->_pid, &status, 0) == -1) {
		free(stream);
		return -1;
	}

	/* Free stream memory */
	free(stream);

	return status;
}
