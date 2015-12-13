#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/inotify.h>


int server_sync_to_client(csiebox_server* server,int conn_fd);
static int prepare_and_sync(char* root,int conn_fd);
static void sync_all(char* root, int conn_fd);
static void sync_file_to_client(char *root,int conn_fd, char* path);
static csiebox_protocol_status sync_file_meta(char* root,int conn_fd, char* path);
static void sync_file_data_to_client(char *root,int conn_fd,char* path);

#define IN_FLAG (IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY)
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

int server_sync_to_client(csiebox_server* server,int connfd) {
  if (!prepare_and_sync(char* root,int conn_fd)) {
    fprintf(stderr, "sync fail\n");
    return 0;
  }
  monitor_home(server);
  fprintf(stderr, "monitor end\n");
  return 1;
}
///

static int prepare_and_sync(char* root,int conn_fd) {
  char* cwd = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(cwd, 0, sizeof(cwd));
  if (getcwd(cwd, PATH_MAX) == 0) {
    fprintf(stderr, "getcwd fail\n");
    fprintf(stderr, "code: %s\n", strerror(errno));
    free(cwd);
    return 0;
  }
  if (chdir(root) != 0) {
    fprintf(stderr, "invalid client path\n");
    free(cwd);
    return 0;
  }
  max_level = 0;
  sync_all(root,conn_fd);
  
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
  header.req.client_id = conn_fd;
  send_message(conn_fd, &header, sizeof(header));
  chdir(cwd);
  free(cwd);
  return 1;
}

static void sync_all(char* root, int conn_fd) {
  char* cwd = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(cwd, 0, sizeof(char) * PATH_MAX);
  if (getcwd(cwd, PATH_MAX) == 0) {
    fprintf(stderr, "getcwd fail\n");
  }
//  add_inotify(client, cwd);
  DIR* dir;
  struct dirent* file;
  struct stat file_stat;
  dir = opendir(".");
  while ((file = readdir(dir)) != NULL) {
    if (strcmp(file->d_name, ".") == 0 ||
        strcmp(file->d_name, "..") == 0) {
	  continue;
    }
    lstat(file->d_name, &file_stat); 
    sync_file(root,conn_fd, file->d_name);
    if ((file_stat.st_mode & S_IFMT) == S_IFDIR) {
      if (chdir(file->d_name) != 0) {
        fprintf(stderr, "bad dir %s\n", file->d_name);
        continue;
      }
      sync_all(root,conn_fd);
      chdir(cwd);
    }
  }
  closedir(dir);
  free(cwd);
  return;
}

static void sync_file_to_client(char *root,int conn_fd, char* path) {
  csiebox_protocol_status status;
  status = sync_file_meta(root,conn_fd, path);
  if (status == CSIEBOX_PROTOCOL_STATUS_MORE) {
    sync_file_data(*root,conn_fd, path);
  }
}

static csiebox_protocol_status sync_file_meta(char* root,int conn_fd, char* path) {
  char* relative = convert_to_relative_path(root, path);
  if (!relative) {
    fprintf(stderr, "convert relative fail: %s\n", path);
    return CSIEBOX_PROTOCOL_STATUS_FAIL;
  }
  csiebox_protocol_meta meta;
  memset(&meta, 0, sizeof(meta));
  meta.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  meta.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  meta.message.header.req.client_id = conn_fd;
  meta.message.header.req.datalen = sizeof(meta) - sizeof(csiebox_protocol_header);
  meta.message.body.pathlen = strlen(relative);
  lstat(path, &(meta.message.body.stat));
  if ((meta.message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
  } else {
    md5_file(path, meta.message.body.hash);
  }
  send_message(conn_fd, &meta, sizeof(meta));
  send_message(conn_fd, relative, strlen(relative));
  free(relative);
  
  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status == CSIEBOX_PROTOCOL_STATUS_FAIL) {
    fprintf(stderr, "sync meta fail: %s\n", path);
    return;
  }
  return header.res.status;
}

static void sync_file_data_to_client(
  char* root,int conn_fd, char* path) {
  fprintf(stderr, "file_data: %s\n", path);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  lstat(path, &stat);
  csiebox_protocol_file file;
  memset(&file, 0, sizeof(file));
  file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
  file.message.header.req.client_id = conn_fd;
  file.message.header.req.datalen = sizeof(file) - sizeof(csiebox_protocol_header);
  if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    file.message.body.datalen = 0;
    fprintf(stderr, "dir datalen: %zu\n", file.message.body.datalen);
    send_message(conn_fd, &file, sizeof(file));
  } else {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "open fail\n");
      file.message.body.datalen = 0;
      send_message(conn_fd, &file, sizeof(file));
    } else {
      file.message.body.datalen = lseek(fd, 0, SEEK_END);
      fprintf(stderr, "else datalen: %zd\n", file.message.body.datalen);
      send_message(conn_fd, &file, sizeof(file));
      lseek(fd, 0, SEEK_SET);
      char buf[4096];
      memset(buf, 0, 4096);
      size_t readlen;
      while ((readlen = read(fd, buf, 4096)) > 0) {
        send_message(conn_fd, buf, readlen);
      }
      close(fd);
    }
  }

  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status != CSIEBOX_PROTOCOL_STATUS_OK) {
    fprintf(stderr, "sync data fail: %s\n", path);
  }
}

static char* convert_to_relative_path(char* root, const char* path) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  if (path[0] == '/') {
    strcpy(ret, path);
  } else {
    char dir[PATH_MAX];
    memset(dir, 0, PATH_MAX);
    getcwd(dir, PATH_MAX);
    sprintf(ret, "%s/%s", dir, path);
  }
  if (strncmp(root, ret, strlen(root)) != 0) {
    free(ret);
    return NULL;
  }
  size_t rootlen = strlen(root);
  size_t retlen = strlen(ret);
  size_t i;
  for (i = 0; i < retlen; ++i) {
    if (i < rootlen) {
      ret[i] = ret[i + rootlen];
    } else {
      ret[i] = 0;
    }
  }
  return ret;
}
