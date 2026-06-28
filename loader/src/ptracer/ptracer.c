#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include <link.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <elf.h>
#include <unistd.h>

#define LOG_TAG "zygisk-injector" LP_SELECT("32", "64")

#include "misc.h"
#include "utils.h"

#include "remote_csoloader.h"

#ifdef __arm__

  /* TODO: I can't express how many detections this likely will have, but
            it is not of high priority. 32-bit apps are going to phase out
            eventually. However, we should investigate possible detections,
            especially when using mprotect to register memory pages. */

bool inject_on_main(int pid, const char *lib_path) {
  LOGI("injecting %s to zygote %d", lib_path, pid);

  /*
    parsing KernelArgumentBlock

    https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/private/KernelArgumentBlock.h;l=30;drc=6d1ee77ee32220e4202c3066f7e1f69572967ad8
  */

  struct user_regs_struct regs = { 0 };

  /* INFO: The character limit for a 32-bit integer is 10 */
  char pid_str[10 + 1];
  snprintf(pid_str, sizeof(pid_str), "%d", pid);

  struct maps_info *map = parse_maps(pid_str);
  if (map == NULL) {
    LOGE("failed to parse remote maps");

    return false;
  }

  if (!get_regs(pid, &regs)) return false;

  uintptr_t arg = (uintptr_t)regs.REG_SP;

  char addr_mem_region[1024];
  get_addr_mem_region(map, arg, addr_mem_region, sizeof(addr_mem_region));

  LOGV("kernel argument %" PRIxPTR " %s", arg, addr_mem_region);

  int argc;
  char **argv = (char **)((uintptr_t *)arg + 1);
  LOGV("argv %p", (void *)argv);

  read_proc(pid, arg, &argc, sizeof(argc));
  LOGV("argc %d", argc);

  char **envp = argv + argc + 1;
  LOGV("envp %p", (void *)envp);

  char **p = envp;
  while (1) {
    uintptr_t *buf;
    read_proc(pid, (uintptr_t)p, &buf, sizeof(buf));

    if (buf == NULL) break;

    p++;
  }

  p++;

  ElfW(auxv_t) *auxv = (ElfW(auxv_t) *)p;

  get_addr_mem_region(map, (uintptr_t)auxv, addr_mem_region, sizeof(addr_mem_region));
  LOGV("auxv %p %s", auxv, addr_mem_region);

  ElfW(auxv_t) *v = auxv;
  uintptr_t entry_addr = 0;
  uintptr_t addr_of_entry_addr = 0;

  while (1) {
    ElfW(auxv_t) buf;

    read_proc(pid, (uintptr_t)v, &buf, sizeof(buf));

    if (buf.a_type == AT_ENTRY) {
      entry_addr = (uintptr_t)buf.a_un.a_val;
      addr_of_entry_addr = (uintptr_t)v + offsetof(ElfW(auxv_t), a_un);

      get_addr_mem_region(map, entry_addr, addr_mem_region, sizeof(addr_mem_region));
      LOGV("entry address %" PRIxPTR " %s (entry=%" PRIxPTR ", entry_addr=%" PRIxPTR ")", entry_addr,
            addr_mem_region, (uintptr_t)v, addr_of_entry_addr);

      break;
    }

    if (buf.a_type == AT_NULL) break;

    v++;
  }

  if (entry_addr == 0) {
    LOGE("failed to get entry");

    return false;
  }

  /* INFO: (-0x0F & ~1) is a value below zero, while the one after "|"
            is an unsigned (must be 0 or greater) value, so we must
            cast the second value to signed long (intptr_t) to avoid
            undefined behavior.

           Replace the program entry with an invalid address. For arm32 compatibility,
            we set the last bit to the same as the entry address.
  */
  uintptr_t break_addr = (uintptr_t)((intptr_t)(-0x0F & ~1) | (intptr_t)((uintptr_t)entry_addr & 1));
  if (!write_proc(pid, (uintptr_t)addr_of_entry_addr, &break_addr, sizeof(break_addr))) return false;

  ptrace(PTRACE_CONT, pid, 0, 0);

  int status;
  wait_for_trace(pid, &status, __WALL);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
    if (!get_regs(pid, &regs)) return false;

    if (((int)regs.REG_IP & ~1) != ((int)break_addr & ~1)) {
      LOGE("stopped at unknown addr %p", (void *) regs.REG_IP);

      return false;
    }

    /* INFO: The linker has been initialized now, we can do dlopen */
    LOGD("stopped at entry");

    /* INFO: Restore entry address */
    if (!write_proc(pid, (uintptr_t) addr_of_entry_addr, &entry_addr, sizeof(entry_addr))) return false;

    /* INFO: Backup registers */
    struct user_regs_struct backup;
    memcpy(&backup, &regs, sizeof(regs));

    free_maps(map);

    map = parse_maps(pid_str);
    if (!map) {
      LOGE("failed to parse remote maps");

      return false;
    }

    struct maps_info *local_map = parse_maps("self");
    if (!local_map) {
      LOGE("failed to parse local maps");

      return false;
    }

    void *libc_return_addr = find_module_return_addr(map, "libc.so");
    LOGD("libc return addr %p", libc_return_addr);

    uintptr_t remote_base = 0;
    size_t remote_size = 0;
    uintptr_t injector_entry = 0;

    if (!remote_csoloader_load_and_resolve_entry(pid, &regs, map, local_map, lib_path, &remote_base, &remote_size, &injector_entry)) {
      LOGE("remote CSOLoader mapping failed");

      free_maps(local_map);
      free_maps(map);

      return false;
    }

    free_maps(local_map);
    free_maps(map);

    long args[3];
    args[0] = (long)remote_base;
    args[1] = (long)remote_size;
    args[2] = 0; /* INFO: tango_flag */

    remote_call(pid, &regs, injector_entry, (uintptr_t)libc_return_addr, args, 3);

    /* INFO: remote_call uses a deliberate SIGSEGV on an invalid return address to regain control.
               If the call faults elsewhere (e.g., inside injector code), REG_IP won't match. */
    bool injector_ok = false;
    #if defined(__arm__)
      injector_ok = (((uintptr_t)regs.REG_IP & ~1u) == ((uintptr_t)libc_return_addr & ~1u));
    #else
      injector_ok = ((uintptr_t)regs.REG_IP == (uintptr_t)libc_return_addr);
    #endif
    if (!injector_ok) {
      char stopped_region[1024];
      struct maps_info *map_after = parse_maps(pid_str);
      if (map_after) {
        get_addr_mem_region(map_after, (uintptr_t)regs.REG_IP, stopped_region, sizeof(stopped_region));

        free_maps(map_after);
      } else {
        snprintf(stopped_region, sizeof(stopped_region), "<maps unavailable>");
      }

      LOGE("injector entry faulted at %p (%s)", (void *)regs.REG_IP, stopped_region);

      /* INFO: Restore registers before reporting failure. */
      backup.REG_IP = (long)entry_addr;

      (void)set_regs(pid, &backup);

      return false;
    }

    /* INFO: Reset pc to entry */
    backup.REG_IP = (long) entry_addr;
    LOGD("invoke entry");

    /* INFO: Restore registers */
    if (!set_regs(pid, &backup)) return false;

    return true;
  } else {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("stopped by other reason: %s", status_str);
  }

  return false;
}

#define STOPPED_WITH(sig, event) (WIFSTOPPED(status) && WSTOPSIG(status) == (sig) && (status >> 16) == (event))
#define WAIT_OR_DIE wait_for_trace(pid, &status, __WALL);
#define CONT_OR_DIE                           \
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) { \
    PLOGE("cont");                            \
                                              \
    return false;                             \
  }

bool trace_zygote(int pid, bool tango_flag) {
  /* INFO: Tango is only used on AArch64 */
  #ifndef __arm__
    (void) tango_flag;
  #endif

  LOGI("start tracing %d (tracer %d)", pid, getpid());

  int status;

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    #ifdef __arm__
      if (tango_flag) {
        /* INFO: For tango injection, we need to seize with PTRACE_O_TRACESYSGOOD to
                   reliably catch the translator's entry point. */
        if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP) == -1) {
          PLOGE("seize for tango");

          return false;
        }
      } else {
        if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP) == -1) {
          PLOGE("seize");

          return false;
        }

        WAIT_OR_DIE;
      }
    #else
      if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP) == -1) {
        PLOGE("seize");

        return false;
      }

      WAIT_OR_DIE;
    #endif
  } else {
    if (ptrace(PTRACE_SEIZE, pid, 0, 0) == -1) {
      PLOGE("seize");

      return false;
    }

    WAIT_OR_DIE;
  }

  #ifdef __arm__
    if (tango_flag) {
      if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        PLOGE("interrupt");

        ptrace(PTRACE_DETACH, pid, 0, 0);

        return false;
      }

      /* INFO: Drain to INTERRUPT's SIGTRAP + EVENT_STOP */
      if (!wait_for_event_stop(pid)) {
        LOGE("Failed to drain to event stop for tango injection");

        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

        return false;
      }

      struct tango_linker_watch watch = { 0 };
      if (!tango_wait_linker_ready(pid, &watch)) {
        LOGE("Failed to wait for linker ready for injection");

        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

        return false;
      }

      /* INFO: Leave syscall-stop state before injection */
      ptrace(PTRACE_CONT, pid, 0, 0);
      if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        PLOGE("Failed to interrupt process for injection");

        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

        return false;
      }

      if (!wait_for_event_stop(pid)) {
        LOGE("Failed to drain to event stop for injection");

        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

        return false;
      }

      const char *lib_path = "/data/adb/modules/rezygisk/lib/libzygisk.so";
      bool result = inject_tango(pid, lib_path, watch.libc_init_resolved, watch.libc_init_got_slot);
      if (!result) LOGE("Failed to inject tango");

      ptrace(PTRACE_DETACH, pid, 0, SIGCONT);

      return result;
    }
  #endif

  if (STOPPED_WITH(SIGSTOP, PTRACE_EVENT_STOP)) {
    char *lib_path = "/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so";
    if (!inject_on_main(pid, lib_path)) {
      LOGE("failed to inject");

      return false;
    }

    LOGD("inject done, continue process");
    if (kill(pid, SIGCONT)) {
      PLOGE("kill");

      return false;
    }

    CONT_OR_DIE
    WAIT_OR_DIE

    if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
      CONT_OR_DIE
      WAIT_OR_DIE

      if (STOPPED_WITH(SIGCONT, 0)) {
        LOGD("received SIGCONT");

        /* INFO: Due to kernel bugs, fixed in 5.16+, ptrace_message (msg of
             PTRACE_GETEVENTMSG) may not represent the current state of
             the process. Because we set some options, which alters the
             ptrace_message, we need to call PTRACE_SYSCALL to reset the
             ptrace_message to 0, the default/normal state.
        */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);

        WAIT_OR_DIE

        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
      }
    } else {
      char status_str[64];
      parse_status(status, status_str, sizeof(status_str));

      LOGE("unknown state %s, not SIGTRAP + EVENT_STOP", status_str);

      ptrace(PTRACE_DETACH, pid, 0, 0);

      return false;
    }
  } else {
    char status_str[64];
    parse_status(status, status_str, sizeof(status_str));

    LOGE("unknown state %s, not SIGSTOP + EVENT_STOP", status_str);

    ptrace(PTRACE_DETACH, pid, 0, 0);

    return false;
  }

  return true;
}
