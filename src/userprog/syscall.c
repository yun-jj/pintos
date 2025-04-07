#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define MAX_SYSCALL 20
#define off_t long long

static void syscall_handler (struct intr_frame *);
static void (*syscalls[MAX_SYSCALL])(struct intr_frame *);

void sys_halt(struct intr_frame* f);
void sys_exit(struct intr_frame* f);
void sys_exec(struct intr_frame* f);
void sys_create(struct intr_frame* f);
void sys_remove(struct intr_frame* f);
void sys_open(struct intr_frame* f);
void sys_wait(struct intr_frame* f);
void sys_filesize(struct intr_frame* f);
void sys_read(struct intr_frame* f);
void sys_write(struct intr_frame* f);
void sys_seek(struct intr_frame* f);
void sys_tell(struct intr_frame* f);
void sys_close(struct intr_frame* f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
  syscalls[SYS_WAIT] = &sys_wait;
  syscalls[SYS_CREATE] = &sys_create;
  syscalls[SYS_REMOVE] = &sys_remove;
  syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  syscalls[SYS_SEEK] = &sys_seek;
  syscalls[SYS_TELL] = &sys_tell;
  syscalls[SYS_CLOSE] =&sys_close;
  syscalls[SYS_READ] = &sys_read;
  syscalls[SYS_FILESIZE] = &sys_filesize;
}

struct thread_file * 
find_file_id (int file_id)
{
  struct list_elem *e;
  struct thread_file * thread_file_temp = NULL;
  struct list *files = &thread_current ()->files;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    thread_file_temp = list_entry (e, struct thread_file, file_elem);
    if (file_id == thread_file_temp->fd)
      return thread_file_temp;
  }
  return false;
}

bool 
is_valid_pointer (void* esp,uint8_t argc)
{
  for (uint8_t i = 0; i < argc; ++i)
  {
    if((!is_user_vaddr(esp)) || 
      (pagedir_get_page(thread_current()->pagedir, esp)==NULL))
      return false;
  }
  return true;
}

void 
exit_special (void)
{
  thread_current()->st_exit = -1;
  thread_exit ();
}

static int 
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

void * 
check_ptr2(const void *vaddr)
{ 
  if (!is_user_vaddr(vaddr))
  {
    exit_special ();
  }
  /* Judge the page */
  void *ptr = pagedir_get_page (thread_current()->pagedir, vaddr);
  if (!ptr)
    exit_special ();
  /* Judge the content of page */
  uint8_t *check_byteptr = (uint8_t *) vaddr;
  for (uint8_t i = 0; i < 4; i++) 
  {
    if (get_user(check_byteptr + i) == -1)
      exit_special ();
  }

  return ptr;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int * p = f->esp;
  check_ptr2(p + 1);
  int type = * (int *)f->esp;
  if(type <= 0 || type >= MAX_SYSCALL)
    exit_special ();

  syscalls[type](f);
}

void 
sys_halt(struct intr_frame* f)
{
  shutdown_power_off();
}

void 
sys_exit (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  *user_ptr++;
  thread_current()->st_exit = *user_ptr;
  thread_exit ();
}

void 
sys_exec (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  check_ptr2(*(user_ptr + 1));
  *user_ptr++;
  f->eax = process_execute((char*)* user_ptr);
}

void 
sys_wait (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}

void 
sys_write (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(*(user_ptr + 2));
  *user_ptr++;
  int fd = *(user_ptr);
  const char * buffer = (const char *)*(user_ptr + 1);
  off_t size = *(user_ptr + 2);

  if (fd == 1)
  {
    putbuf(buffer,size);
    f->eax = size;
  }
  else
  {
    /* Write to Files */
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f();
      f->eax = file_write (thread_file_temp->file, buffer, size);
      release_lock_f();
    } 
    else
      f->eax = 0;
  }
}

void 
sys_create(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  check_ptr2(*(user_ptr + 1));
  *user_ptr++;
  if (strlen((const char *)*user_ptr) == 0 ||
      strlen((const char *)*user_ptr) >= 128)
  {
    f->eax = 0;
    return;
  }
  acquire_lock_f();
  f->eax = filesys_create((const char *)*user_ptr, *(user_ptr+1));
  f->eax = (f->eax) & 0x0000000f;
  release_lock_f();
}

void 
sys_remove(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  check_ptr2(*(user_ptr + 1));
  *user_ptr++;
  acquire_lock_f();
  f->eax = filesys_remove((const char *)*user_ptr);
  release_lock_f();
}

void 
sys_open (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);
  check_ptr2 (*(user_ptr + 1));
  *user_ptr++;
  acquire_lock_f ();
  struct file * file_opened = filesys_open((const char *)*user_ptr);
  release_lock_f ();
  struct thread * t = thread_current();
  if (file_opened)
  {
    struct thread_file *thread_file_temp = malloc(sizeof(struct thread_file));
    thread_file_temp->fd = t->max_file_fd++;
    thread_file_temp->file = file_opened;
    list_push_back (&t->files, &thread_file_temp->file_elem);
    f->eax = thread_file_temp->fd;
  } 
  else
    f->eax = -1;
}

void 
sys_filesize (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  *user_ptr++;
  struct thread_file * thread_file_temp = find_file_id(*user_ptr);
  if (thread_file_temp)
  {
    acquire_lock_f();
    f->eax = file_length(thread_file_temp->file);
    release_lock_f();
  } 
  else
    f->eax = -1;
}

void 
sys_read (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  *user_ptr++;
  int fd = *user_ptr;
  uint8_t * buffer = (uint8_t*)*(user_ptr+1);
  off_t size = *(user_ptr + 2);

  if (!is_valid_pointer(buffer, 1) ||
      !is_valid_pointer(buffer + size, 1))
    exit_special();

  if (fd == 0)
  {
    for (int i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;
  }
  else
  {
    struct thread_file * thread_file_temp = find_file_id(*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f();
      f->eax = file_read(thread_file_temp->file, buffer, size);
      release_lock_f();
    } 
    else
      f->eax = -1;
  }
}

void 
sys_seek(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  *user_ptr++;
  struct thread_file *file_temp = find_file_id(*user_ptr);
  if (file_temp)
  {
    acquire_lock_f();
    file_seek(file_temp->file, *(user_ptr+1));
    release_lock_f();
  }
}

void 
sys_tell (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2(user_ptr + 1);
  *user_ptr++;
  struct thread_file *thread_file_temp = find_file_id(*user_ptr);

  if (thread_file_temp)
  {
    acquire_lock_f();
    f->eax = file_tell(thread_file_temp->file);
    release_lock_f();
  }
  else
    f->eax = -1;
}

void 
sys_close (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);
  *user_ptr++;
  struct thread_file * opened_file = find_file_id(*user_ptr);
  if (opened_file)
  {
    acquire_lock_f ();
    file_close (opened_file->file);
    release_lock_f ();
    list_remove (&opened_file->file_elem);
    free (opened_file);
  }
}